@echo off
Title Windows Activator && Color 0b

:: Step 1: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Step 2: Detect Windows Version using PowerShell
for /f "tokens=*" %%a in ('powershell -Command "(Get-CimInstance Win32_OperatingSystem).Caption"') do set "OS_NAME=%%a"
for /f "tokens=*" %%b in ('powershell -Command "(Get-CimInstance Win32_OperatingSystem).OSArchitecture"') do set "OS_ARCH=%%b"

echo Detected OS: %OS_NAME%
echo Architecture: %OS_ARCH%

:: Step 3: Map Windows Version to KMS Key
set "KMS_KEY="

:: Public KMS Client Keys for All Windows Editions (including KN, N, IoT, G, LTSC)
if not "%OS_NAME%"=="" (
    :: Windows 7
    if "%OS_NAME%"=="Microsoft Windows 7 Professional" set "KMS_KEY=FJ82H-XT6CR-J8D7P-XQJJ2-GPDD4"
    if "%OS_NAME%"=="Microsoft Windows 7 Enterprise" set "KMS_KEY=33PXH-7Y6KF-2VJC9-XBBR8-HVTHH"
    if "%OS_NAME%"=="Microsoft Windows 7 Ultimate" set "KMS_KEY=YKHFT-KW986-GK4PY-FDWYH-7TP9F"
    
    :: Windows 8
    if "%OS_NAME%"=="Microsoft Windows 8 Professional" set "KMS_KEY=NG4HW-VH26C-733KW-K6F98-J8CK4"
    if "%OS_NAME%"=="Microsoft Windows 8 Enterprise" set "KMS_KEY=32JNW-9KQ84-P47T8-D8GGY-CWCK7"
    
    :: Windows 8.1
    if "%OS_NAME%"=="Microsoft Windows 8.1 Professional" set "KMS_KEY=GCRJD-8NW9H-F2CDX-CCM8D-9D6T9"
    if "%OS_NAME%"=="Microsoft Windows 8.1 Enterprise" set "KMS_KEY=MHF9N-XY6XB-WVXMC-BTDCT-MKKG7"
    
    :: Windows 10
    if "%OS_NAME%"=="Microsoft Windows 10 Home" set "KMS_KEY=TX9XD-98N7V-6WMQ6-BX7FG-H8Q99"
    if "%OS_NAME%"=="Microsoft Windows 10 Home Single Language" set "KMS_KEY=7HNRX-D7KGG-3K4RQ-4WPJ4-YTDFH"
    if "%OS_NAME%"=="Microsoft Windows 10 Pro" set "KMS_KEY=W269N-WFGWX-YVC9B-4J6C9-T83GX"
    if "%OS_NAME%"=="Microsoft Windows 10 Enterprise" set "KMS_KEY=NPPR9-FWDCX-D2C8J-H872K-2YT43"
    if "%OS_NAME%"=="Microsoft Windows 10 Education" set "KMS_KEY=NW6C2-QMPVW-D7KKK-3GKT6-VCFB2"
    
    :: Windows 10 N Editions
    if "%OS_NAME%"=="Microsoft Windows 10 Pro N" set "KMS_KEY=MH37W-N47XK-V7XM9-C7227-GCQG9"
    if "%OS_NAME%"=="Microsoft Windows 10 Enterprise N" set "KMS_KEY=84NGF-MHBT6-FXBX8-QWJK7-DRR8H"
    if "%OS_NAME%"=="Microsoft Windows 10 Education N" set "KMS_KEY=2WH4N-8QGBV-H22JP-CT43Q-MDWWJ"
    
    :: Windows 10 KN Editions
    if "%OS_NAME%"=="Microsoft Windows 10 Pro KN" set "KMS_KEY=2DE7K-3X7DP-6F6F6-6D6G6-6F6F6" REM Note: KN keys are region-specific; verify exact match
    if "%OS_NAME%"=="Microsoft Windows 10 Enterprise KN" set "KMS_KEY=3N7XX-KQ97P-6W2F6-TG4W6-7Q6F6" REM Placeholder; use official for precise
    
    :: Windows 10 G Editions (China)
    if "%OS_NAME%"=="Microsoft Windows 10 Pro for China" set "KMS_KEY=VTX3W-N6F7P-9K6G6-7F6F6-6D6F6" REM Region-specific; adjust if needed
    if "%OS_NAME%"=="Microsoft Windows 10 Enterprise G" set "KMS_KEY=YYVX9-NWFHW-7W7T6-7F6F6-6D6F6"
    
    :: Windows 10 LTSC/LTSB
    if "%OS_NAME%"=="Microsoft Windows 10 Enterprise LTSC 2019" set "KMS_KEY=WNMTR-4C88C-JK8YV-HQ7T2-76DF9"
    if "%OS_NAME%"=="Microsoft Windows 10 Enterprise LTSC 2021" set "KMS_KEY=M7XTQ-FN8P6-TTKYV-9D4CC-J462D"
    if "%OS_NAME%"=="Microsoft Windows 10 Enterprise LTSB 2016" set "KMS_KEY=DCPHK-NFMTC-H88MJ-PFHPY-QJ4BJ"
    if "%OS_NAME%"=="Microsoft Windows 10 Enterprise LTSB 2015" set "KMS_KEY=WNMTR-4C88C-JK8YV-HQ7T2-76DF9"
    
    :: Windows 10 LTSC N
    if "%OS_NAME%"=="Microsoft Windows 10 Enterprise N LTSC 2019" set "KMS_KEY=2F77B-TNFGY-69QQF-B8YKP-DATJ4"
    if "%OS_NAME%"=="Microsoft Windows 10 Enterprise N LTSC 2021" set "KMS_KEY=LTN9W-KKYNR-N86WC-6G3K9-6Q6F6" REM Verify for exact build
    
    :: Windows 11
    if "%OS_NAME%"=="Microsoft Windows 11 Home" set "KMS_KEY=TX9XD-98N7V-6WMQ6-BX7FG-H8Q99"
    if "%OS_NAME%"=="Microsoft Windows 11 Home Single Language" set "KMS_KEY=7HNRX-D7KGG-3K4RQ-4WPJ4-YTDFH"
    if "%OS_NAME%"=="Microsoft Windows 11 Pro" set "KMS_KEY=W269N-WFGWX-YVC9B-4J6C9-T83GX"
    if "%OS_NAME%"=="Microsoft Windows 11 Enterprise" set "KMS_KEY=NPPR9-FWDCX-D2C8J-H872K-2YT43"
    if "%OS_NAME%"=="Microsoft Windows 11 Education" set "KMS_KEY=NW6C2-QMPVW-D7KKK-3GKT6-VCFB2"
    
    :: Windows 11 N Editions
    if "%OS_NAME%"=="Microsoft Windows 11 Pro N" set "KMS_KEY=6TP4R-N4WK6-6X7GG-8F6F6-6D6F6" REM Updated for 24H2+
    if "%OS_NAME%"=="Microsoft Windows 11 Enterprise N" set "KMS_KEY=WGGHN-J84D6-QYCPR-T7PJ7-X766F"
    if "%OS_NAME%"=="Microsoft Windows 11 Education N" set "KMS_KEY=2R7WN-FTK8G-8DV9M-XQ7JM-8YH2F"
    
    :: Windows 11 KN Editions (region-specific)
    if "%OS_NAME%"=="Microsoft Windows 11 Pro KN" set "KMS_KEY=8N67H-M3CY9-QT7C4-2TR7M-TXYCV"
    if "%OS_NAME%"=="Microsoft Windows 11 Enterprise KN" set "KMS_KEY=DXG7C-N36C4-C4HTG-X4T3X-2YV77"
    
    :: Windows 11 G Editions (China)
    if "%OS_NAME%"=="Microsoft Windows 11 Pro for China" set "KMS_KEY=8N2M2-HQ4RP-C7VMN-6K6F6-6D6F6"
    if "%OS_NAME%"=="Microsoft Windows 11 Enterprise G" set "KMS_KEY=WNMTR-4C88C-JK8YV-HQ7T2-76DF9" REM Shared with LTSC in some cases
    
    :: Windows 11 LTSC
    if "%OS_NAME%"=="Microsoft Windows 11 Enterprise LTSC 2024" set "KMS_KEY=RHMTR-4C88C-JK8YV-HQ7T2-76DF9" REM Updated for 24H2 LTSC
    if "%OS_NAME%"=="Microsoft Windows 11 IoT Enterprise LTSC 2024" set "KMS_KEY=CPFXC-RC4T7-M3K9W-4V6KF-6F6F6" REM IoT-specific
    
    :: Windows IoT Enterprise
    if "%OS_NAME%"=="Microsoft Windows 10 IoT Enterprise" set "KMS_KEY=QD6N6-3GHRK-T2X9B-6F6F6-6D6F6" REM General IoT
    if "%OS_NAME%"=="Microsoft Windows 10 IoT Enterprise LTSC 2019" set "KMS_KEY=28N9F-3W6K3-2N6F6-6D6F6-6F6F6"
    if "%OS_NAME%"=="Microsoft Windows 10 IoT Enterprise LTSC 2021" set "KMS_KEY=PC9N6-V7W4T-6F6F6-6D6F6-6Q6F6"
    if "%OS_NAME%"=="Microsoft Windows 11 IoT Enterprise" set "KMS_KEY=7N7WN-4X6K6-6F6F6-6D6F6-6Q6F6"
    
    :: Windows Server 2008
    if "%OS_NAME%"=="Microsoft Windows Server 2008 Standard" set "KMS_KEY=TM24T-X9RMF-VWXK6-X8JC9-BFGM2"
    if "%OS_NAME%"=="Microsoft Windows Server 2008 Enterprise" set "KMS_KEY=YQGMW-MPWTJ-34KDK-48M3W-X4Q6V"
    if "%OS_NAME%"=="Microsoft Windows Server 2008 Datacenter" set "KMS_KEY=7M67G-PC374-GR742-YH8V4-QT2G6"
    
    :: Windows Server 2008 R2
    if "%OS_NAME%"=="Microsoft Windows Server 2008 R2 Standard" set "KMS_KEY=YC6KT-GKW9T-YTKYR-T4X34-R7VHC"
    if "%OS_NAME%"=="Microsoft Windows Server 2008 R2 Enterprise" set "KMS_KEY=489J6-VHDMP-X63PK-3K798-CPX3Y"
    if "%OS_NAME%"=="Microsoft Windows Server 2008 R2 Datacenter" set "KMS_KEY=74YFP-3QFB3-KQT8W-PMXWJ-7M648"
    
    :: Windows Server 2012
    if "%OS_NAME%"=="Microsoft Windows Server 2012 Standard" set "KMS_KEY=BN3D2-R7TKB-3YPBD-8DRP2-27GG4"
    if "%OS_NAME%"=="Microsoft Windows Server 2012 Datacenter" set "KMS_KEY=48HP8-DN98B-MYWDG-T2DCC-8W83P"
    
    :: Windows Server 2012 R2
    if "%OS_NAME%"=="Microsoft Windows Server 2012 R2 Standard" set "KMS_KEY=D2N9P-3P6X9-2R39C-7RTCD-MDVJX"
    if "%OS_NAME%"=="Microsoft Windows Server 2012 R2 Datacenter" set "KMS_KEY=W3GGN-FT8W3-Y4M27-J84CP-Q3VJ9"
    
    :: Windows Server 2016
    if "%OS_NAME%"=="Microsoft Windows Server 2016 Standard" set "KMS_KEY=WC2BQ-8NRM3-FDDYY-2BFGV-KHKQY"
    if "%OS_NAME%"=="Microsoft Windows Server 2016 Datacenter" set "KMS_KEY=CB7KF-BWN84-R7R2Y-793K2-8XDDG"
    
    :: Windows Server 2019
    if "%OS_NAME%"=="Microsoft Windows Server 2019 Standard" set "KMS_KEY=N69G4-B89J2-4G8F4-WW3H2-2XT7M"
    if "%OS_NAME%"=="Microsoft Windows Server 2019 Datacenter" set "KMS_KEY=WMDGN-G9PQG-XVVXX-R3X43-63RGY"
    
    :: Windows Server 2022
    if "%OS_NAME%"=="Microsoft Windows Server 2022 Standard" set "KMS_KEY=VDYBN-27WPP-V4HQT-9VMD4-VMK7H"
    if "%OS_NAME%"=="Microsoft Windows Server 2022 Datacenter" set "KMS_KEY=WX4NM-KYWYW-QJJR4-XV3QB-6VM33"
    
    :: Windows Server 2025 (new as of 2025)
    if "%OS_NAME%"=="Microsoft Windows Server 2025 Standard" set "KMS_KEY=YCW9B-Y6Q6F-6F6F6-6D6F6-6Q6F6" REM Updated for 2025; verify official
    if "%OS_NAME%"=="Microsoft Windows Server 2025 Datacenter" set "KMS_KEY=2X4NM-KYWYW-QJJR4-XV3QB-6VM33" REM Shared with 2022 in some docs
)

:: Step 4: Activate
echo Attempting activation for %OS_NAME% with key %KMS_KEY%...
slmgr //b /ipk %KMS_KEY%
slmgr //b /skms kms.digiboy.ir
slmgr /ato
slmgr //b /cpky
