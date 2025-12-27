#requires -Version 5.1
#requires -RunAsAdministrator

<#
.SYNOPSIS
    Antivirus - Enterprise-Grade EDR in PowerShell
.DESCRIPTION
    Complete standalone security solution: Real-time prevention, detection, response, memory scanning, exploit mitigation
.AUTHOR
    Gorstak
.VERSION
    2.0.0
#>

param(
    [switch]$Uninstall
)

# Global configuration
$Global:EDR = @{
    BasePath = "$env:ProgramData\Antivirus"
    LogPath = "$env:ProgramData\Antivirus\Logs"
    QuarantinePath = "$env:ProgramData\Antivirus\Quarantine"
    ScanInterval = 18
    MaxLogSizeMB = 100
    MaxQuarantineGB = 5
    ThreatScore = @{ Critical=100; High=85; Medium=50; Low=25 }
    Actions = @{ Critical="Block"; High="Terminate"; Medium="Alert"; Low="Log" }
}

# Initialize paths
if(!(Test-Path $Global:EDR.BasePath)) { 
    New-Item -Path $Global:EDR.BasePath -ItemType Directory -Force | Out-Null 
}
foreach($p in @($Global:EDR.LogPath, $Global:EDR.QuarantinePath)) {
    if(!(Test-Path $p)) { New-Item -Path $p -ItemType Directory -Force | Out-Null }
}

# ============================================================================
# Core Logging
# ============================================================================

function Write-EDRLog {
    param([string]$Msg, [string]$Level = "Info", [hashtable]$Meta = @{})
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = @{ Timestamp=$ts; Level=$Level; Message=$Msg; Host=$env:COMPUTERNAME; Meta=$Meta } | ConvertTo-Json -Compress
    $logFile = Join-Path $Global:EDR.LogPath "edr-$(Get-Date -Format 'yyyyMMdd').json"
    Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue
    if($Level -in @("Critical","Error","Warning","Detection")) {
        Write-Output "[$ts] $Level : $Msg"
    }
}

# ============================================================================
# THREAT PREVENTION ENGINE
# ============================================================================

class PreventionEngine {
    [hashtable] CheckProcess([object]$proc) {
        $score = 0
        $iocs = @()
        $cmd = $proc.CommandLine
        
        # Exclude the antivirus script itself from detection
        if($cmd -match "\\ProgramData\\Antivirus\\Antivirus\.ps1") {
            return @{ Score=0; IOCs=@(); Process=$proc }
        }
        
        # LOLBins with suspicious arguments
        $lolbinPatterns = @{
            "certutil" = "-decode|-urlcache|http"
            "bitsadmin" = "/transfer|/download|http"
            "mshta" = "http|javascript:|vbscript:"
            "regsvr32" = "/s|/i:http|scrobj\.dll"
            "rundll32" = "javascript:|http|\.cpl"
            "wmic" = "process call create|/node"
            "msiexec" = "/quiet|/q|http"
            "powershell" = "-e[nc]|-w\s+h|-nop|-noni|-sta\s+-nop"
            "cmd" = "/c echo|&&|^\||powershell"
            "wscript|cscript" = "http|\.vbs.*http"
            "regasm|regsvcs" = "http"
            "installutil" = "http|\/logfile"
            "msbuild" = "http|\.csproj"
            "csc" = "/out.*\.exe"
            "ieexec" = "http"
            "odbcconf" = "/a|\.rsp"
        }
        
        foreach($tool in $lolbinPatterns.Keys) {
            if($proc.Name -match $tool) {
                if($cmd -match $lolbinPatterns[$tool]) {
                    $score += 85
                    $iocs += "LOLBin abuse: $tool with suspicious args"
                }
            }
        }
        
        # Mimikatz-like behavior: accessing LSASS memory
        if($cmd -match "lsass|sekurlsa|logonpasswords") {
            $score += 95
            $iocs += "Credential dumping behavior detected"
        }
        
        # Any process reading lsass memory (behavioral)
        if($proc.Name -match "^(?!werfault|taskmgr|procexp)" -and $cmd -match "lsass") {
            $score += 90
            $iocs += "LSASS memory access attempt"
        }
        
        # PsExec-like behavior: remote service creation
        if($cmd -match "\\\\.*\\IPC\$|\\\\.*\\admin\$|sc.*create.*binpath") {
            $score += 85
            $iocs += "Lateral movement behavior"
        }
        
        # Procdump-like behavior: process dumping
        if($cmd -match "\.dmp|MiniDumpWriteDump") {
            $score += 80
            $iocs += "Memory dumping behavior"
        }

        # Generic malicious command patterns
        if($cmd -match "invoke-|iex|downloadstring|downloadfile|net\.webclient|start-bitstransfer") {
            $score += 80
            $iocs += "Malicious command pattern"
        }

        # Parent-child anomaly detection
        $parent = Get-CimInstance Win32_Process -Filter "ProcessId=$($proc.ParentProcessId)" -EA 0
        if($proc.Name -match "svchost|lsass|csrss|smss" -and $parent.Name -notmatch "services|wininit|winlogon|ntoskrnl") {
            $score += 70
            $iocs += "Process injection detected"
        }
        
        # Unsigned binaries from temp
        if($proc.ExecutablePath -match "\\temp\\|\\appdata\\roaming\\") {
            try {
                $sig = Get-AuthenticodeSignature -FilePath $proc.ExecutablePath -EA 0
                if($sig.Status -ne "Valid") {
                    $score += 40
                    $iocs += "Unsigned binary in temp"
                }
            } catch {}
        }
        
        # Token manipulation check
        try {
            $handle = [System.Diagnostics.Process]::GetProcessById($proc.ProcessId)
            if($handle.StartInfo.Verb -eq "runas" -and $handle.Parent.Name -notmatch "explorer") {
                $score += 35
                $iocs += "Privilege escalation"
            }
        } catch {}
        
        return @{ Score=$score; IOCs=$iocs; Process=$proc }
    }
    
    [bool] BlockProcess([int]$procId, [string]$reason) {
        try {
            Write-EDRLog -Msg "BLOCKING process $procId - $reason" -Level "Critical"
            Stop-Process -Id $procId -Force -EA Stop
            return $true
        } catch {
            Write-EDRLog -Msg "Failed to block $procId : $_" -Level "Error"
            return $false
        }
    }
}

# ============================================================================
# MEMORY SCANNER
# ============================================================================

class MemoryScanner {
    [array] ScanProcessMemory() {
        $threats = @()
        $processes = Get-Process | Where-Object { $_.Id -ne $PID }
        
        foreach($proc in $processes) {
            try {
                # Module injection detection - suspicious DLL loads
                $suspiciousMods = @()
                foreach($mod in $proc.Modules) {
                    if($mod.FileName -match "\\temp\\.*\.(dll|exe)$|\\appdata\\roaming\\.*\.(dll|exe)$") {
                        try {
                            $sig = Get-AuthenticodeSignature -FilePath $mod.FileName -ErrorAction Stop
                            if($sig.Status -ne "Valid") {
                                $suspiciousMods += $mod
                            }
                        } catch { }
                    }
                }
                
                if($suspiciousMods.Count -gt 0) {
                    $threats += @{
                        Type = "ModuleInjection"
                        PID = $proc.Id
                        Name = $proc.Name
                        Modules = ($suspiciousMods.FileName -join "; ")
                        Severity = "High"
                        Score = 85
                        IOCs = "Unsigned modules loaded from temp/appdata"
                    }
                }
                
                # Reflective DLL injection detection (modules without disk backing)
                $memoryOnlyMods = @()
                foreach($mod in $proc.Modules) {
                    if([string]::IsNullOrEmpty($mod.FileName)) {
                        $memoryOnlyMods += $mod
                    }
                }
                
                if($memoryOnlyMods.Count -gt 0) {
                    $threats += @{
                        Type = "ReflectiveDLLInjection"
                        PID = $proc.Id
                        Name = $proc.Name
                        ModuleCount = $memoryOnlyMods.Count
                        Severity = "Critical"
                        Score = 90
                        IOCs = "Memory-only modules detected (no disk backing)"
                    }
                }
                
                # Only flag CLR in truly non-.NET processes
                $clrMods = $proc.Modules | Where-Object { $_.ModuleName -match "^(clr|mscoree)" }
                $legitCLRProcs = "powershell|devenv|msbuild|aspnet|w3wp|iisexpress|vshost|ServiceHub|MSBuild"
                if($clrMods -and $proc.Name -notmatch $legitCLRProcs) {
                    $threats += @{
                        Type = "CLRInjection"
                        PID = $proc.Id
                        Name = $proc.Name
                        Severity = "High"
                        Score = 80
                        IOCs = ".NET runtime injected into non-.NET process"
                    }
                }
                
            } catch { }
        }
        return $threats
    }
    
    [hashtable] CreateModuleBaseline([int]$procId) {
        try {
            $proc = Get-Process -Id $procId -EA 0
            $baseline = @{
                PID = $procId
                Name = $proc.Name
                Timestamp = Get-Date
                Modules = @()
            }
            foreach($mod in $proc.Modules) {
                $baseline.Modules += @{
                    Name = $mod.ModuleName
                    Path = $mod.FileName
                    Size = $mod.Size
                }
            }
            return $baseline
        } catch {
            return @{}
        }
    }
    
    [array] DetectModuleChanges([hashtable]$baseline) {
        $changes = @()
        try {
            $proc = Get-Process -Id $baseline.PID -EA 0
            $currentMods = @{}
            foreach($mod in $proc.Modules) {
                $currentMods[$mod.ModuleName] = $mod
            }
            
            $baselineMods = @{}
            foreach($mod in $baseline.Modules) {
                $baselineMods[$mod.Name] = $mod
            }
            
            # Detect new modules
            foreach($modName in $currentMods.Keys) {
                if(!$baselineMods.ContainsKey($modName)) {
                    $changes += @{
                        Type = "NewModuleLoaded"
                        Module = $modName
                        Path = $currentMods[$modName].FileName
                        Score = 70
                    }
                }
            }
            
        } catch { }
        return $changes
    }
}

# ============================================================================
# NETWORK INTERCEPTOR
# ============================================================================

class NetworkInterceptor {
    [array] MonitorConnections() {
        $threats = @()
        $conns = Get-NetTCPConnection -State Established -EA 0
        
        foreach($c in $conns) {
            $score = 0
            $iocs = @()
            
            # Only flag known C2 ports
            if($c.RemotePort -in @(4444,5555,6666,7777,8888,31337,1337,4443)) {
                $score += 70
                $iocs += "Known C2 port: $($c.RemotePort)"
            }
            
            # Only flag script engines with non-browser traffic to unusual ports
            $proc = Get-Process -Id $c.OwningProcess -EA 0
            if($proc.Name -match "^(powershell|cmd|wscript|cscript|mshta)$" -and 
               $c.RemotePort -notin @(80,443,8080,8443)) {
                $score += 50
                $iocs += "Script engine unusual network activity"
            }
            
            # Only create threat if score is actually high
            if($score -ge 70) {
                $threats += @{
                    Type = "Network"
                    PID = $c.OwningProcess
                    Process = $proc.Name
                    Remote = "$($c.RemoteAddress):$($c.RemotePort)"
                    Severity = "High"
                    Score = $score
                    IOCs = $iocs -join ", "
                }
            }
        }
        return $threats
    }
    
    [void] BlockConnection([int]$procId) {
        try {
            Stop-Process -Id $procId -Force
            Write-EDRLog -Msg "Blocked malicious connection by terminating PID $procId" -Level "Critical"
        } catch {
            Write-EDRLog -Msg "Failed to block connection: $_" -Level "Error"
        }
    }
}

# ============================================================================
# FILESYSTEM GUARDIAN
# ============================================================================

class FilesystemGuardian {
    [System.IO.FileSystemWatcher]$Watcher
    [hashtable]$FileChanges = @{}
    
    FilesystemGuardian() {
        $this.Watcher = New-Object System.IO.FileSystemWatcher
        $this.Watcher.Path = "C:\"
        $this.Watcher.Filter = "*.*"
        $this.Watcher.IncludeSubdirectories = $true
        $this.Watcher.NotifyFilter = [System.IO.NotifyFilters]::FileName -bor [System.IO.NotifyFilters]::LastWrite
    }
    
    [array] DetectRansomware() {
        $threats = @()
        
        try {
            $ransomExtensions = "\.encrypted$|\.locked$|\.crypto$|\.cerber$|\.locky$|\.zepto$"
            $ransomNotes = "README.*DECRYPT|HOW.*DECRYPT|RESTORE.*FILES|YOUR.*FILES.*ENCRYPTED"
            
            $suspiciousFiles = Get-ChildItem "C:\Users" -Recurse -File -EA 0 | Where-Object { 
                $_.LastWriteTime -gt (Get-Date).AddMinutes(-5) -and 
                ($_.Extension -match $ransomExtensions -or $_.Name -match $ransomNotes)
            } | Select-Object -First 20
            
            if($suspiciousFiles.Count -gt 10) {
                $threats += @{
                    Type = "Ransomware"
                    FilesEncrypted = $suspiciousFiles.Count
                    Extensions = ($suspiciousFiles.Extension | Select-Object -Unique) -join ", "
                    Severity = "Critical"
                    Score = 95
                    IOCs = "Mass file encryption detected"
                }
            }
        } catch { }
        
        return $threats
    }
    
    [void] QuarantineFile([string]$path) {
        try {
            $qDir = $Global:EDR.QuarantinePath
            $dest = Join-Path $qDir ([System.IO.Path]::GetFileName($path) + ".quarantine")
            Move-Item -Path $path -Destination $dest -Force
            Write-EDRLog -Msg "Quarantined: $path" -Level "Warning"
        } catch {
            Write-EDRLog -Msg "Quarantine failed for $path : $_" -Level "Error"
        }
    }
}

# ============================================================================
# REGISTRY PROTECTOR
# ============================================================================

class RegistryProtector {
    [array] DetectPersistence() {
        $threats = @()
        
        $maliciousPatterns = "powershell.*-e[nc].*|iex\s+.*downloadstring|invoke-webrequest.*iex|mimikatz|psexec.*-s\s|procdump.*lsass|certutil.*-decode.*\.exe"
        
        $keys = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        )
        
        foreach($keyPath in $keys) {
            try {
                $props = Get-ItemProperty $keyPath -EA 0
                foreach($prop in $props.PSObject.Properties) {
                    if($prop.Name -notmatch "^PS" -and $prop.Value -match $maliciousPatterns) {
                        $threats += @{
                            Type = "RegistryPersistence"
                            Key = $keyPath
                            Name = $prop.Name
                            Value = $prop.Value
                            Severity = "High"
                            Score = 75
                            IOCs = "Malicious persistence mechanism"
                        }
                    }
                }
            } catch { }
        }
        return $threats
    }
    
    [void] RemovePersistence([string]$key, [string]$name) {
        try {
            Remove-ItemProperty -Path $key -Name $name -Force -EA Stop
            Write-EDRLog -Msg "Removed persistence: $key\$name" -Level "Warning"
        } catch {
            Write-EDRLog -Msg "Failed to remove persistence: $_" -Level "Error"
        }
    }
}

# ============================================================================
# EXPLOIT MITIGATOR
# ============================================================================

class ExploitMitigator {
    [array] DetectExploits() {
        $threats = @()
        
        try {
            $recentDrivers = Get-WinEvent -FilterHashtable @{LogName='System';Id=7045} -MaxEvents 10 -EA 0 |
                Where-Object { $_.TimeCreated -gt (Get-Date).AddHours(-1) }
            
            foreach($evt in $recentDrivers) {
                $driverPath = $evt.Properties[4].Value
                if($driverPath -match "\\temp\\|\\users\\|\\downloads\\") {
                    $threats += @{
                        Type = "SuspiciousDriver"
                        Path = $driverPath
                        Severity = "Critical"
                        Score = 90
                        IOCs = "Driver loaded from suspicious location"
                    }
                }
            }
        } catch { }
        
        return $threats
    }
}

# ============================================================================
# BEHAVIORAL ANALYZER
# ============================================================================

class BehavioralAnalyzer {
    [hashtable]$ProcessHistory = @{}
    
    [array] AnalyzeBehavior() {
        $threats = @()
        
        try {
            $procs = Get-CimInstance Win32_Process
            
            foreach($proc in $procs) {
                $processId = $proc.ProcessId
                $parentId = $proc.ParentProcessId
                
                # Count direct children of each parent
                $children = $procs | Where-Object { $_.ParentProcessId -eq $parentId -and $_.Name -match "^(cmd|powershell|wscript|cscript)$" }
                
                if($children.Count -gt 15) {
                    $parent = Get-Process -Id $parentId -EA 0
                    $threats += @{
                        Type = "ProcessSpawning"
                        ParentPID = $parentId
                        ParentName = $parent.Name
                        ChildrenCount = $children.Count
                        Severity = "High"
                        Score = 80
                        IOCs = "Excessive script engine spawning detected"
                    }
                    break
                }
            }
        } catch { }
        
        return $threats
    }
}

# ============================================================================
# MASTER DETECTION ENGINE
# ============================================================================

class MasterDetector {
    [PreventionEngine]$Prevention
    [MemoryScanner]$Memory
    [NetworkInterceptor]$Network
    [FilesystemGuardian]$Filesystem
    [RegistryProtector]$Registry
    [ExploitMitigator]$Exploit
    [BehavioralAnalyzer]$Behavior
    [hashtable]$ModuleBaselines = @{}
    
    MasterDetector() {
        $this.Prevention = [PreventionEngine]::new()
        $this.Memory = [MemoryScanner]::new()
        $this.Network = [NetworkInterceptor]::new()
        $this.Filesystem = [FilesystemGuardian]::new()
        $this.Registry = [RegistryProtector]::new()
        $this.Exploit = [ExploitMitigator]::new()
        $this.Behavior = [BehavioralAnalyzer]::new()
    }
    
    [array] ExecuteFullScan() {
        $allThreats = @()
        
        Write-Output "[SCAN] Process prevention..."
        $procs = Get-CimInstance Win32_Process
        foreach($proc in $procs) {
            $result = $this.Prevention.CheckProcess($proc)
            if($result.Score -ge $Global:EDR.ThreatScore.High) {
                $allThreats += @{
                    Type = "ProcessThreat"
                    Severity = if($result.Score -ge $Global:EDR.ThreatScore.Critical){"Critical"}elseif($result.Score -ge $Global:EDR.ThreatScore.High){"High"}else{"Medium"}
                    PID = $proc.ProcessId
                    ProcessName = $proc.Name
                    CommandLine = $proc.CommandLine
                    IOCs = $result.IOCs -join ", "
                    Score = $result.Score
                    Data = $result
                }
            }
        }
        
        Write-Output "[SCAN] Memory & module injection analysis..."
        $memThreats = $this.Memory.ScanProcessMemory()
        foreach($t in $memThreats) {
            $allThreats += @{
                Type = "MemoryThreat"
                Severity = if($t.Score -ge $Global:EDR.ThreatScore.Critical){"Critical"}else{"High"}
                PID = $t.PID
                ProcessName = $t.ProcessName
                IOCs = $t.IOCs -join ", "
                Score = $t.Score
                Data = $t
            }
            
            if($t.PID -and !$this.ModuleBaselines.ContainsKey($t.PID)) {
                $this.ModuleBaselines[$t.PID] = $this.Memory.CreateModuleBaseline($t.PID)
            }
        }
        
        foreach($procId in $this.ModuleBaselines.Keys) {
            $changes = $this.Memory.DetectModuleChanges($this.ModuleBaselines[$procId])
            foreach($change in $changes) {
                if($change.Score -ge $Global:EDR.ThreatScore.Medium) {
                    $allThreats += @{
                        Type = "ModuleChange"
                        PID = $procId
                        Details = $change
                        Score = $change.Score
                        Severity = if($change.Score -ge 80) { "High" } else { "Medium" }
                        IOCs = "Runtime module modification"
                        ProcessName = try { (Get-Process -Id $procId -EA 0).Name } catch { "Unknown" }
                    }
                }
            }
        }
        
        $activePIDs = (Get-Process).Id
        $this.ModuleBaselines.Keys | Where-Object { $_ -notin $activePIDs } | ForEach-Object {
            $this.ModuleBaselines.Remove($_)
        }
        
        Write-Output "[SCAN] Network connections..."
        $netThreats = $this.Network.MonitorConnections()
        foreach($t in $netThreats) {
            $allThreats += @{
                Type = "NetworkThreat"
                Severity = if($t.Score -ge $Global:EDR.ThreatScore.High){"High"}else{"Medium"}
                PID = $t.ProcessId
                ProcessName = $t.ProcessName
                IOCs = "$($t.RemoteAddress):$($t.RemotePort)"
                Score = $t.Score
                Data = $t
            }
        }
        
        Write-Output "[SCAN] Ransomware detection..."
        $fsThreats = $this.Filesystem.DetectRansomware()
        foreach($t in $fsThreats) {
            $allThreats += @{
                Type = "FilesystemThreat"
                Severity = "Critical"
                PID = $t.ProcessId
                ProcessName = $t.ProcessName
                IOCs = "$($t.FileCount) files encrypted/deleted"
                Score = $t.Score
                Data = $t
            }
        }
        
        Write-Output "[SCAN] Persistence mechanisms..."
        $regThreats = $this.Registry.DetectPersistence()
        foreach($t in $regThreats) {
            $allThreats += @{
                Type = "PersistenceThreat"
                Severity = "High"
                Key = $t.Key
                Name = $t.Name
                IOCs = "$($t.Key)\$($t.Name)"
                Score = $t.Score
                Data = $t
            }
        }
        
        Write-Output "[SCAN] Exploit detection..."
        $exploitThreats = $this.Exploit.DetectExploits()
        foreach($t in $exploitThreats) {
            $allThreats += @{
                Type = "ExploitThreat"
                Severity = "Critical"
                PID = $t.ProcessId
                ProcessName = $t.ProcessName
                IOCs = $t.Technique
                Score = $t.Score
                Data = $t
            }
        }
        
        Write-Output "[SCAN] Behavioral analysis..."
        $behaviorThreats = $this.Behavior.AnalyzeBehavior()
        foreach($t in $behaviorThreats) {
            $allThreats += @{
                Type = "BehavioralThreat"
                Severity = "High"
                PID = $t.ParentPID
                ProcessName = $t.ProcessName
                IOCs = $t.Pattern
                Score = $t.Score
                Data = $t
            }
        }
        
        return $allThreats
    }
}

# ============================================================================
# RESPONSE ORCHESTRATOR
# ============================================================================

class ResponseOrchestrator {
    [MasterDetector]$Detector
    
    ResponseOrchestrator([MasterDetector]$det) {
        $this.Detector = $det
    }
    
    [void] Respond([hashtable]$threat) {
        $action = $Global:EDR.Actions[$threat.Severity]
        Write-EDRLog -Msg "THREAT: $($threat.Type) | Severity: $($threat.Severity) | IOCs: $($threat.IOCs)" -Level "Detection" -Meta $threat
        
        switch($action) {
            "Block" {
                $this.BlockThreat($threat)
            }
            "Terminate" {
                $this.TerminateThreat($threat)
            }
            "Alert" {
                $this.AlertOnly($threat)
            }
            "Log" {
                # Already logged
            }
        }
    }
    
    [void] BlockThreat([hashtable]$threat) {
        $procId = $null
        if($threat.PID) { $procId = $threat.PID }
        elseif($threat.ProcessId) { $procId = $threat.ProcessId }
        
        if($procId) {
            $this.Detector.Prevention.BlockProcess($procId, $threat.Type)
        }
        
        # Remove persistence
        if($threat.Type -eq "RegistryPersistence") {
            $this.Detector.Registry.RemovePersistence($threat.Key, $threat.Name)
        }
    }
    
    [void] TerminateThreat([hashtable]$threat) {
        $procId = $null
        if($threat.PID) { $procId = $threat.PID }
        elseif($threat.ProcessId) { $procId = $threat.ProcessId }
        
        if($procId) {
            try {
                $proc = Get-Process -Id $procId -EA SilentlyContinue
                if($proc) {
                    Write-Output "TERMINATING: PID $procId ($($threat.ProcessName)) - $($threat.Type)"
                    Stop-Process -Id $procId -Force -EA Stop
                    Write-EDRLog -Msg "TERMINATED: PID $procId ($($threat.ProcessName)) for $($threat.Type)" -Level "Warning"
                } else {
                    Write-Output "Process $procId already terminated"
                }
            } catch {
                Write-EDRLog -Msg "Failed to terminate $procId : $_" -Level "Error"
            }
        } else {
            Write-Output "No PID found for $($threat.Type) - cannot terminate"
        }
    }
    
    [void] AlertOnly([hashtable]$threat) {
        $alertFile = Join-Path $Global:EDR.LogPath "alerts.json"
        $threat | ConvertTo-Json -Depth 5 | Add-Content $alertFile
    }
}

# ============================================================================
# MAIN AGENT LOOP
# ============================================================================

function Start-EDRAgent {
    Write-EDRLog "EDR Agent started on $env:COMPUTERNAME" "Info"
    
    Write-Output "Antivirus Protection Started"
    Write-Output "Press Ctrl+C to stop"
    Write-Output ""
    
    $detector = [MasterDetector]::new()
    $responder = [ResponseOrchestrator]::new($detector)
    
    $scanCount = 0
    while($true) {
        $scanCount++
        Write-Output "[Scan $scanCount] $(Get-Date -Format 'HH:mm:ss') - Running detection engines..."
        
        $threats = $detector.ExecuteFullScan()
        
        if($threats.Count -gt 0) {
            Write-Output "THREATS DETECTED: $($threats.Count)"
            Write-Output ""
            
            foreach($threat in $threats) {
                $responder.Respond($threat)
            }
        } else {
            Write-Output "No threats detected"
        }
        
        Write-Output ""
        Start-Sleep -Seconds $Global:EDR.ScanInterval
    }
}

# ============================================================================
# SELF-INSTALLATION FUNCTIONALITY
# ============================================================================

function Install-EDRAntivirus {
    Write-Host "Installing Antivirus to system..." -ForegroundColor Cyan
    
    $installPath = $Global:EDR.BasePath
    $scriptPath = Join-Path $installPath "Antivirus.ps1"
    
    try {
        # Directory already created during initialization
        
        Copy-Item -Path $PSCommandPath -Destination $scriptPath -Force
        
        $taskArg = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`""
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $taskArg
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        
        Register-ScheduledTask -TaskName "Antivirus-Protection" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
        
        Write-Output "Installed to: $scriptPath"
        Write-Output "Scheduled task created: Antivirus-Protection"
        
    } catch {
        Write-Output "Installation error: $($_)"
        exit 1
    }
}

function Uninstall-Antivirus {
    Write-Output "Uninstalling Antivirus from system..." -ForegroundColor Cyan
    
    # Check for admin privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if(!$isAdmin) {
        Write-Output "ERROR: Requires Administrator privileges"
        exit 1
    }
    
    try {
        $task = Get-ScheduledTask -TaskName "Antivirus-Protection" -ErrorAction SilentlyContinue
        if($task) {
            Unregister-ScheduledTask -TaskName "Antivirus-Protection" -Confirm:$false
            Write-Output "Removed scheduled task"
        }
        
        $installPath = $Global:EDR.BasePath
        if(Test-Path $installPath) {
            Remove-Item -Path $installPath -Recurse -Force
            Write-Output "Removed installation directory"
        }
        
        $edrPath = $Global:EDR.LogPath
        if(Test-Path $edrPath) {
            Remove-Item -Path $edrPath -Recurse -Force
            Write-Output "Removed EDR data directory"
        }
        
        Write-Output "Uninstall complete"
        
    } catch {
        Write-Output "Uninstall error: $($_)"
        exit 1
    }
}

# ============================================================================
# Entry Point
# ============================================================================

if($Uninstall) {
    Uninstall-Antivirus
} else {
    # Check if already installed
    $installPath = "$env:ProgramData\Antivirus\Antivirus.ps1"
    $isInstalled = (Test-Path $installPath)
    $runningFromInstall = ($PSCommandPath -eq $installPath)
    
    # If not installed, install first
    if(!$isInstalled) {
        Install-EDRAntivirus
        Write-Output ""
        Write-Output "Installation complete. Starting monitoring now..."
        Write-Output ""
        # Start monitoring immediately from the installed location
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$installPath"
        exit 0
    }
    
    # If already installed and running from install location, start monitoring
    if($runningFromInstall) {
        Start-EDRAgent
    } else {
        # Running from a different location but already installed
        Write-Output "Antivirus is already installed and running from: $installPath"
        Write-Output "Launching monitoring session..."
        Write-Output ""
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$installPath"
        exit 0
    }
}
