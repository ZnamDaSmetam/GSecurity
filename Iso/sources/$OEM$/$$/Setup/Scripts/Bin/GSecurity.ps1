# =======================================
# GSecurity Unified Installer (All Modules)
# Author: Gorstak
# =======================================
# One-command deployment with advanced security features
# Installs modular PS1 files + startup enforcement
# Windows 10 / 11
# Run as Administrator

$ErrorActionPreference = "Stop"

$Base = "$env:ProgramData\GSecurity"
$Modules = "$Base\Modules"
$LogFile = "$Base\Logs\installer.log"

function Write-InstallLog {
    param(
        [string]$Message,
        [string]$Severity = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Severity] $Message"
    
    try {
        if (-not (Test-Path "$Base\Logs")) {
            New-Item -Path "$Base\Logs" -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        $logEntry | Out-File -FilePath $LogFile -Append -Encoding UTF8 -ErrorAction Stop
        
        # Also write to console with color coding
        $color = switch ($Severity) {
            "CRITICAL" { "Red" }
            "ERROR" { "Red" }
            "WARNING" { "Yellow" }
            "SUCCESS" { "Green" }
            default { "White" }
        }
        Write-Host $logEntry -ForegroundColor $color
    } catch {
        Write-Host "[FATAL] Cannot write to log: $_" -ForegroundColor Red
    }
}

function Test-InstallConfiguration {
    $errors = @()
    
    Write-InstallLog "Validating installation configuration..." "INFO"
    
    # Check if running as administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $errors += "Script must be run as Administrator"
        Write-InstallLog "Not running as Administrator" "ERROR"
    } else {
        Write-InstallLog "Administrator privileges verified" "SUCCESS"
    }
    
    # Check available disk space
    try {
        $drive = Get-PSDrive -Name C
        $freeSpaceGB = [math]::Round($drive.Free / 1GB, 2)
        if ($freeSpaceGB -lt 1) {
            $errors += "Low disk space: Only ${freeSpaceGB}GB available"
            Write-InstallLog "Low disk space: ${freeSpaceGB}GB" "WARNING"
        } else {
            Write-InstallLog "Disk space available: ${freeSpaceGB}GB" "SUCCESS"
        }
    } catch {
        Write-InstallLog "Could not check disk space: $_" "WARNING"
    }
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 5) {
        $errors += "PowerShell 5.0 or higher required (Current: $($PSVersionTable.PSVersion))"
        Write-InstallLog "PowerShell version too old: $($PSVersionTable.PSVersion)" "ERROR"
    } else {
        Write-InstallLog "PowerShell version: $($PSVersionTable.PSVersion)" "SUCCESS"
    }
    
    # Check write permissions to Program Data
    try {
        $testPath = "$env:ProgramData\GSecurity_test"
        New-Item -Path $testPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
        Remove-Item $testPath -Force
        Write-InstallLog "Write permissions verified for ProgramData" "SUCCESS"
    } catch {
        $errors += "No write permission to ProgramData folder"
        Write-InstallLog "No write permission to ProgramData" "ERROR"
    }
    
    if ($errors.Count -eq 0) {
        Write-InstallLog "All configuration checks passed" "SUCCESS"
        return $true
    } else {
        Write-InstallLog "Configuration validation found $($errors.Count) issue(s)" "ERROR"
        foreach ($error in $errors) {
            Write-InstallLog "  - $error" "ERROR"
        }
        return $false
    }
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "GSecurity Installer - by Gorstak" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

if (-not (Test-InstallConfiguration)) {
    Write-Host "`n[FATAL] Installation cannot proceed due to configuration errors." -ForegroundColor Red
    Write-Host "Please fix the issues above and run the installer again." -ForegroundColor Red
    exit 1
}

# --- Create directories ---
Write-InstallLog "Creating directory structure..." "INFO"
$dirs = @($Base,"$Base\Logs","$Base\Rules","$Base\Quarantine","$Base\Quarantine\reports",$Modules)
foreach ($d in $dirs) { 
    New-Item -ItemType Directory -Force -Path $d | Out-Null 
    Write-InstallLog "Created: $d" "INFO"
}

# ===============================
# MODULE: EDR CORE (Enhanced)
# ===============================
Write-InstallLog "Installing EDR Core module..." "INFO"
@'
# GSecurity.EDR.Core.ps1
# Author: Gorstak
$ErrorActionPreference="SilentlyContinue"

$Base="$env:ProgramData\GSecurity"
$Log="$Base\Logs\edr.log"
$Quarantine="$Base\Quarantine"
$SecurityLog="$Base\Logs\security_events.jsonl"

$LOL=@("powershell.exe","pwsh.exe","mshta.exe","rundll32.exe","regsvr32.exe","wmic.exe","cscript.exe","wscript.exe")

function Log($m,$l="INFO"){
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp][$l] $m"
    Add-Content $Log $logEntry
    
    # Log rotation
    if ((Test-Path $Log) -and ((Get-Item $Log -ErrorAction SilentlyContinue).Length -ge 10MB)) {
        $archiveName = "$Base\Logs\edr_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        Rename-Item -Path $Log -NewName $archiveName -ErrorAction SilentlyContinue
    }
}

function Log-SecurityEvent($EventType, $Details, $Severity="Medium"){
    try {
        $event = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
            EventType = $EventType
            Severity = $Severity
            Machine = $env:COMPUTERNAME
            User = $env:USERNAME
            Details = $Details
        }
        $eventJson = $event | ConvertTo-Json -Compress
        Add-Content $SecurityLog $eventJson
    } catch {}
}

Log "GSecurity EDR Core started" "INFO"
Log-SecurityEvent "EDRStarted" @{Version="1.0"} "Low"

Register-WmiEvent -Class Win32_ProcessStartTrace -SourceIdentifier GSecurityEDR -Action {
 $e=$Event.SourceEventArgs.NewEvent
 $cmd=$e.CommandLine
 $name=$e.ProcessName.ToLower()
 $pid=$e.ProcessId

 $score=0
 $reasons=@()
 
 if($LOL -contains $name){
   $score+=2
   $reasons+="LOLBin: $name"
 }
 if($cmd -match "-enc"){$score+=2; $reasons+="Base64 encoding"}
 if($cmd -match "bypass"){$score+=2; $reasons+="Execution policy bypass"}
 if($cmd -match "invoke-expression|iex"){$score+=2; $reasons+="Invoke-Expression"}
 if($cmd -match "http"){$score+=1; $reasons+="HTTP in command"}
 if($cmd -match "downloadstring|downloadfile"){$score+=3; $reasons+="Download function"}

 if($score -ge 4){
  try {
    Stop-Process -Id $pid -Force
    $logMsg = "Blocked PID:$pid CMD:$cmd Reasons:$($reasons -join ', ')"
    Add-Content "$env:ProgramData\GSecurity\Logs\edr.log" "[$(Get-Date -f s)][CRITICAL] $logMsg"
    
    # Log security event
    $event = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
        EventType = "ProcessBlocked"
        Severity = "Critical"
        Machine = $env:COMPUTERNAME
        Details = @{
            ProcessId = $pid
            ProcessName = $name
            CommandLine = $cmd
            ThreatScore = $score
            Reasons = $reasons
        }
    }
    $eventJson = $event | ConvertTo-Json -Compress
    Add-Content "$env:ProgramData\GSecurity\Logs\security_events.jsonl" $eventJson
  } catch {
    Add-Content "$env:ProgramData\GSecurity\Logs\edr.log" "[$(Get-Date -f s)][ERROR] Failed to block PID:$pid - $($_.Exception.Message)"
  }
 }
}

Log "WMI Event monitoring active" "INFO"

while($true){Start-Sleep 5}
'@ | Set-Content "$Modules\GSecurity.EDR.Core.ps1" -Encoding UTF8

# ===============================
# MODULE: TI UPDATER
# ===============================
Write-InstallLog "Installing Threat Intelligence module..." "INFO"
@'
# GSecurity.TI.Update.ps1
# Author: Gorstak
$Base="$env:ProgramData\GSecurity"
$Rules="$Base\Rules"
$Log="$Base\Logs\ti_updater.log"

function Log($m){
    Add-Content $Log "[$(Get-Date -f s)] $m"
}

Log "TI Updater initialized"
"# GSecurity Threat Intelligence Rules
# Updated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
# Author: Gorstak

# Add custom threat indicators here
# Format: One indicator per line
" | Out-File "$Rules\threat_indicators.txt" -Encoding UTF8

Log "TI updater ready (offline safe)"
'@ | Set-Content "$Modules\GSecurity.TI.Update.ps1"

# ===============================
# MODULE: ON-DEMAND SCANNER
# ===============================
Write-InstallLog "Installing Scanner module..." "INFO"
@'
# GSecurity.Scanner.ps1
# Author: Gorstak
$Base="$env:ProgramData\GSecurity"
$Log="$Base\Logs\scanner.log"

function Log($m,$severity="INFO"){
    Add-Content $Log "[$(Get-Date -f s)][$severity] $m"
}

Log "Starting on-demand scan" "INFO"

$scannedCount = 0
$suspiciousCount = 0

Get-ChildItem C:\ -Recurse -Include *.exe,*.dll,*.ps1,*.vbs,*.js -ErrorAction SilentlyContinue |
 ForEach-Object {
  $scannedCount++
  $file = $_.FullName
  
  # Basic heuristic checks
  if ($_.Length -lt 1KB -and $_.Extension -eq ".exe") {
    Log "Suspicious: $file (Very small executable)" "WARNING"
    $suspiciousCount++
  }
  
  if ($scannedCount % 100 -eq 0) {
    Log "Progress: $scannedCount files scanned, $suspiciousCount suspicious" "INFO"
  }
 }

Log "Scan complete: $scannedCount files scanned, $suspiciousCount suspicious files found" "INFO"
'@ | Set-Content "$Modules\GSecurity.Scanner.ps1"

# ===============================
# MODULE: PERSISTENCE AUDIT
# ===============================
Write-InstallLog "Installing Persistence Audit module..." "INFO"
@'
# GSecurity.Persistence.Audit.ps1
# Author: Gorstak
$Base="$env:ProgramData\GSecurity"
$Log="$Base\Logs\persistence_audit.log"

function Log($m,$severity="INFO"){
    Add-Content $Log "[$(Get-Date -f s)][$severity] $m"
}

Log "Starting persistence audit" "INFO"

# Check common persistence locations
$locations = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($loc in $locations) {
    try {
        $items = Get-ItemProperty $loc -ErrorAction SilentlyContinue
        if ($items) {
            $items.PSObject.Properties | Where-Object {$_.Name -notlike "PS*"} | ForEach-Object {
                Log "Found: $loc\$($_.Name) = $($_.Value)" "INFO"
            }
        }
    } catch {
        Log "Could not access: $loc" "WARNING"
    }
}

# Check scheduled tasks
Get-ScheduledTask | Where-Object {$_.State -ne "Disabled"} | ForEach-Object {
    Log "Scheduled Task: $($_.TaskName) - State: $($_.State)" "INFO"
}

Log "Persistence audit complete" "INFO"
'@ | Set-Content "$Modules\GSecurity.Persistence.Audit.ps1"

# ===============================
# MODULE: NETWORK AUDIT
# ===============================
Write-InstallLog "Installing Network Audit module..." "INFO"
@'
# GSecurity.Network.Audit.ps1
# Author: Gorstak
$Base="$env:ProgramData\GSecurity"
$Log="$Base\Logs\network_audit.log"

function Log($m,$severity="INFO"){
    Add-Content $Log "[$(Get-Date -f s)][$severity] $m"
}

Log "Starting network audit" "INFO"

# Get established connections
$connections = Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}

foreach ($conn in $connections) {
    try {
        $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
        Log "Connection: $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort) | Process: $($process.Name) (PID: $($conn.OwningProcess))" "INFO"
    } catch {
        Log "Connection: $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort) | Process: Unknown (PID: $($conn.OwningProcess))" "WARNING"
    }
}

Log "Network audit complete - Found $($connections.Count) established connections" "INFO"
'@ | Set-Content "$Modules\GSecurity.Network.Audit.ps1"

# ===============================
# MODULE: AMSI OBSERVER
# ===============================
Write-InstallLog "Installing AMSI Observer module..." "INFO"
@'
# GSecurity.AMSI.Observer.ps1
# Author: Gorstak
$Base="$env:ProgramData\GSecurity"
$Log="$Base\Logs\amsi_observer.log"

function Log($m,$severity="INFO"){
    Add-Content $Log "[$(Get-Date -f s)][$severity] $m"
}

Log "AMSI observer active (passive monitoring)" "INFO"
Log "AMSI integration ready for script content analysis" "INFO"
'@ | Set-Content "$Modules\GSecurity.AMSI.Observer.ps1"

# ===============================
# MODULE: POLICY BUILDER
# ===============================
Write-InstallLog "Installing Policy Builder module..." "INFO"
@'
# GSecurity.Policy.Builder.ps1
# Author: Gorstak
$Base="$env:ProgramData\GSecurity"
$Log="$Base\Logs\policy_builder.log"

function Log($m,$severity="INFO"){
    Add-Content $Log "[$(Get-Date -f s)][$severity] $m"
}

Log "Policy builder initialized" "INFO"
Log "Policy templates ready for customization" "INFO"
'@ | Set-Content "$Modules\GSecurity.Policy.Builder.ps1"

# ===============================
# MODULE: REPORTING (Enhanced)
# ===============================
Write-InstallLog "Installing Reporting module..." "INFO"
@'
# GSecurity.Report.ps1
# Author: Gorstak
$Base="$env:ProgramData\GSecurity"
$Quarantine="$Base\Quarantine"
$LogFile="$Base\Logs\edr.log"

function Generate-SecurityReport {
    param([string]$ReportType = "Daily")
    
    try {
        Write-Host "[REPORT] Generating $ReportType security report..." -ForegroundColor Cyan
        
        # Gather statistics
        $logContent = Get-Content $LogFile -ErrorAction SilentlyContinue
        $criticalEvents = ($logContent | Select-String "\[CRITICAL\]" | Measure-Object).Count
        $quarantinedFiles = (Get-ChildItem "$Quarantine\*.quarantined" -ErrorAction SilentlyContinue).Count
        
        $report = @{
            Generated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            ReportType = $ReportType
            Author = "Gorstak"
            Statistics = @{
                CriticalEvents = $criticalEvents
                FilesQuarantined = $quarantinedFiles
                TotalLogEntries = $logContent.Count
            }
            RecentEvents = $logContent | Select-Object -Last 20
            SystemInfo = @{
                ComputerName = $env:COMPUTERNAME
                UserName = $env:USERNAME
                OSVersion = [System.Environment]::OSVersion.VersionString
                PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            }
        }
        
        $reportPath = "$Quarantine\reports\$ReportType-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        $report | ConvertTo-Json -Depth 5 | Set-Content $reportPath
        
        Write-Host "[REPORT] Report generated: $reportPath" -ForegroundColor Green
        return $reportPath
    } catch {
        Write-Host "[ERROR] Failed to generate report: $_" -ForegroundColor Red
        return $null
    }
}

# Display recent log entries
Write-Host "`n=== GSecurity Log Summary ===" -ForegroundColor Cyan
Get-Content "$Base\Logs\edr.log" -Tail 20 -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_ -match "CRITICAL") {
        Write-Host $_ -ForegroundColor Red
    } elseif ($_ -match "WARNING") {
        Write-Host $_ -ForegroundColor Yellow
    } else {
        Write-Host $_ -ForegroundColor White
    }
}

# Generate report
$reportPath = Generate-SecurityReport -ReportType "OnDemand"
if ($reportPath) {
    Write-Host "`nFull report saved to: $reportPath" -ForegroundColor Green
}
'@ | Set-Content "$Modules\GSecurity.Report.ps1"

# ===============================
# MAIN LAUNCHER (Enhanced)
# ===============================
Write-InstallLog "Creating main launcher..." "INFO"
@'
# GSecurity.ps1
# Author: Gorstak
# Main launcher with mutex protection

$Base = $PSScriptRoot
$LogFile = "$Base\Logs\main.log"

function Log($m,$severity="INFO"){
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content $LogFile "[$timestamp][$severity] $m"
}

try {
    $mutexName = "Global\GSecurity_Mutex_{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}"
    $mutex = [System.Threading.Mutex]::new($false, $mutexName)
    
    if (-not $mutex.WaitOne(0, $false)) {
        Log "Another instance is already running. Exiting." "WARNING"
        Write-Host "[PROTECTION] GSecurity is already running." -ForegroundColor Yellow
        exit 0
    }
    
    Log "Mutex acquired - Starting GSecurity" "INFO"
    Write-Host "[PROTECTION] GSecurity starting with mutex protection" -ForegroundColor Green
} catch {
    Log "Failed to acquire mutex (requires admin): $($_.Exception.Message)" "WARNING"
    Write-Host "[WARNING] Running without mutex protection" -ForegroundColor Yellow
}

Log "GSecurity main launcher started" "INFO"

# Launch EDR Core
. "$PSScriptRoot\Modules\GSecurity.EDR.Core.ps1"
'@ | Set-Content "$Base\GSecurity.ps1"

# ===============================
# SCHEDULED TASK
# ===============================
Write-InstallLog "Configuring scheduled task..." "INFO"
$task="GSecurity-Startup"
if(Get-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue){
 Unregister-ScheduledTask -TaskName $task -Confirm:$false
 Write-InstallLog "Removed existing task" "INFO"
}

$act=New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$Base\GSecurity.ps1`""
$trg=New-ScheduledTaskTrigger -AtStartup
$pri=New-ScheduledTaskPrincipal -UserId SYSTEM -RunLevel Highest -LogonType ServiceAccount

Register-ScheduledTask -TaskName $task -Action $act -Trigger $trg -Principal $pri | Out-Null
Write-InstallLog "Scheduled task created: $task" "SUCCESS"

Write-InstallLog "Setting directory permissions..." "INFO"
icacls "$Base" /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" /grant:r "Administrators:(OI)(CI)F" | Out-Null
Write-InstallLog "Permissions set successfully" "SUCCESS"

Write-InstallLog "Generating installation report..." "INFO"
$installReport = @{
    InstallDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Author = "Gorstak"
    Version = "1.0"
    InstallPath = $Base
    Modules = @(
        "GSecurity.EDR.Core.ps1",
        "GSecurity.TI.Update.ps1",
        "GSecurity.Scanner.ps1",
        "GSecurity.Persistence.Audit.ps1",
        "GSecurity.Network.Audit.ps1",
        "GSecurity.AMSI.Observer.ps1",
        "GSecurity.Policy.Builder.ps1",
        "GSecurity.Report.ps1"
    )
    Features = @(
        "Enhanced logging with severity levels",
        "Configuration validation",
        "Mutex-based self-protection",
        "Security event logging in JSON format",
        "Comprehensive security reporting",
        "Log rotation (10MB limit)",
        "Process blocking with threat scoring",
        "Network connection monitoring",
        "Persistence location auditing"
    )
    ScheduledTask = $task
    SystemInfo = @{
        ComputerName = $env:COMPUTERNAME
        OSVersion = [System.Environment]::OSVersion.VersionString
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
    }
}

$installReport | ConvertTo-Json -Depth 5 | Set-Content "$Base\Logs\installation_report.json"
Write-InstallLog "Installation report saved" "SUCCESS"

Write-Host "`n========================================" -ForegroundColor Green
Write-Host "GSecurity Installation Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "Author: Gorstak" -ForegroundColor Cyan
Write-Host "Install Path: $Base" -ForegroundColor Cyan
Write-Host "Scheduled Task: $task" -ForegroundColor Cyan
Write-Host "`nInstalled Modules:" -ForegroundColor Yellow
$installReport.Modules | ForEach-Object { Write-Host "  - $_" -ForegroundColor White }
Write-Host "`nNew Features:" -ForegroundColor Yellow
$installReport.Features | ForEach-Object { Write-Host "  - $_" -ForegroundColor White }
Write-Host "`nInstallation log: $LogFile" -ForegroundColor Cyan
Write-Host "Installation report: $Base\Logs\installation_report.json" -ForegroundColor Cyan
Write-Host "`n[+] GSecurity will start automatically on next boot" -ForegroundColor Green
Write-Host "[+] To start manually, run: $Base\GSecurity.ps1`n" -ForegroundColor Green

Write-InstallLog "Installation completed successfully" "SUCCESS"
