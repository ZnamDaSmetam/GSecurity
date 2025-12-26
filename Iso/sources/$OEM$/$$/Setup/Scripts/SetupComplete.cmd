@echo off

:: Script Metadata
set "SCRIPT_NAME=GSecurity"
set "SCRIPT_VERSION=6.0.0"
set "SCRIPT_UPDATED=06.10.2025"
set "AUTHOR=Gorstak"
Title GSecurity && Color 0b

:: Step 1: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Step 2: Initialize environment
setlocal EnableExtensions EnableDelayedExpansion

:: Step 3: Move to the script directory
cd /d %~dp0
cd Bin

:: Step 4: Execute PowerShell (.ps1) files alphabetically
echo Executing PowerShell scripts...
for /f "tokens=*" %%A in ('dir /b /o:n *.ps1') do (
    echo Running %%A...
        start "" /b powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File "%%A"
)

:: Step 5: Execute CMD (.cmd) files alphabetically
echo Executing CMD scripts...
for /f "tokens=*" %%B in ('dir /b /o:n *.cmd') do (
    echo Running %%B...
    call "%%B"
)

:: Step 6: Execute Registry (.reg) files alphabetically
echo Executing Registry files...
for /f "tokens=*" %%C in ('dir /b /o:n *.reg') do (
    echo Merging %%C...
    reg import "%%C"
)

echo Script completed successfully.
exit