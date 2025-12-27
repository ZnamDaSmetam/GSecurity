@echo off

:: Bios tweaks
set bcd=%windir%\system32\bcdedit.exe
%bcd% /set nx AlwaysOff
%bcd% /set ems No
%bcd% /set bootems No
%bcd% /set integrityservices disable
%bcd% /set tpmbootentropy ForceDisable
%bcd% /set bootmenupolicy Legacy
%bcd% /set debug No
%bcd% /set disableelamdrivers Yes
%bcd% /set isolatedcontext No
%bcd% /set allowedinmemorysettings 0x0
%bcd% /set vm NO
%bcd% /set vsmlaunchtype Off
%bcd% /set configaccesspolicy Default
%bcd% /set MSI Default
%bcd% /set usephysicaldestination No
%bcd% /set usefirmwarepcisettings No
%bcd% /set sos no
%bcd% /set pae ForceDisable
%bcd% /set tscsyncpolicy legacy
%bcd% /set hypervisorlaunchtype off
%bcd% /set useplatformclock false
%bcd% /set useplatformtick no
%bcd% /set disabledynamictick yes
%bcd% /set x2apicpolicy disable
%bcd% /set uselegacyapicmode yes



