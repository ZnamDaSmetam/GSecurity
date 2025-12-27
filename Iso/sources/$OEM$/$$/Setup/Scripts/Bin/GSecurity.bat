@echo off

:: Elevate
>nul 2>&1 fsutil dirty query %systemdrive% || echo CreateObject^("Shell.Application"^).ShellExecute "%~0", "ELEVATED", "", "runas", 1 > "%temp%\uac.vbs" && "%temp%\uac.vbs" && exit /b
DEL /F /Q "%temp%\uac.vbs"

:: Perms
takeown /f %windir%\System32\Oobe\useroobe.dll /A
icacls %windir%\System32\Oobe\useroobe.dll /reset
icacls %windir%\System32\Oobe\useroobe.dll /inheritance:r
icacls "%systemdrive%\Users" /remove "Everyone"
takeown /f "%USERPROFILE%\Desktop" /A /R /D y
icacls "%USERPROFILE%\Desktop" /reset
icacls "%USERPROFILE%\Desktop" /inheritance:r
icacls "%USERPROFILE%\Desktop" /grant:r "*S-1-2-1":(OI)(CI)F /t /l /q /c
takeown /f "C:\Users\Public\Desktop" /A /R /D y
icacls "C:\Users\Public\Desktop" /reset
icacls "C:\Users\Public\Desktop" /inheritance:r
icacls "C:\Users\Public\Desktop" /grant:r "*S-1-2-1":(OI)(CI)F /t /l /q /c
takeown /f "C:\Windows\System32\wbem" /A
icacls "C:\Windows\System32\wbem" /reset
icacls "C:\Windows\System32\wbem" /inheritance:r
takeown /f %windir%\system32\consent.exe /A
icacls %windir%\system32\consent.exe /reset
icacls %windir%\system32\consent.exe /inheritance:r
icacls %windir%\system32\consent.exe /grant:r "Console Logon":RX
for %%d in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    if exist "%%d:\" (
	takeown /f "%%d:\" /A
	icacls "%%d:\" /remove "Authenticated Users"
	icacls "%%d:\" /grant "Authenticated Users":(OI)(CI)(RD,REA,RC,RA,X,GR)
        icacls "%%d:\" /remove "Users"
	icacls "%%d:\" /grant "Users":(OI)(CI)(RD,REA,RC,RA,X,GR)
	icacls "%%d:\" /remove "System"
	icacls "%%d:\" /grant "System":(OI)(CI)(RD,REA,RC,RA,X,GR)
        icacls "%%d:\" /remove "Administrators"
	icacls "%%d:\" /grant "Administrators":(OI)(CI)(RD,REA,RC,RA,X,GR)
	icacls "%%d:\" /setowner "NT SERVICE\TrustedInstaller"
	)
)
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d "5" /f
Reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorUser" /t REG_DWORD /d "1" /f

:: Services
sc config VNC start= disabled
sc stop VNC
sc config FileZilla Server start= disabled
sc stop FileZilla Server
sc config OpenSSH start= disabled
sc stop OpenSSH
sc config vsftpd start= disabled
sc stop vsftpd
sc config TeamViewer start= disabled
sc stop TeamViewer
sc config AnyDesk start= disabled
sc stop AnyDesk
sc config LogMeIn start= disabled
sc stop LogMeIn
sc config Radmin start= disabled
sc stop Radmin
sc config SsdpSrv start= disabled
sc stop SsdpSrv
sc config upnphost start= disabled
sc stop upnphost
sc config TelnetServer start= disabled
sc stop TelnetServer
sc config sshd start= disabled
sc stop sshd
sc config ftpsvc start= disabled
sc stop ftpsvc
sc config seclogon start= disabled
sc stop seclogon
sc config LanmanWorkstation start= disabled
sc stop LanmanWorkstation
sc config LanmanServer start= disabled
sc stop LanmanServer
sc config WinRM start= disabled
sc stop WinRM
sc config RemoteRegistry start= disabled
sc stop RemoteRegistry
sc config SNMP start= disabled
sc stop SNMP

:: Users
net user defaultuser0 /delete

:: Script dir
cd /d %~dp0

:: Registry
for /f "tokens=*" %%C in ('dir /b /o:n *.reg') do (
    reg import "%%C"
)

:: Restart
shutdown /r /t 0