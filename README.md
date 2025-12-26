# GSecurity

So, when you first install Windows, as soon as you reach the desktop, an elevated User OOBE Servers will execute, one instance each for the Local Service and Network Service SIDs.
There will be no UAC prompt (no need for your confirmation as an admin) because there's a registry key called COMAutoApprovalList, in which the GUID of that component is allowed to bypass UAC. So at that point, you already have two remote users active.
Unlike Linux, where you can't access a subfolder without permission to its parent folder, on Windows it's enough to have permission anywhere in the path to access the resource. For someone from the internet to access that, File and Printer Sharing must be enabled. 
However, if they have credentials (i.e., username and password), File and Printer Sharing isn’t even required. That means anyone that can execute useroobe.dll can create an invisible user on your pc and have access to all the data.

Once hacker sees your ip, they can see your LAN, and do all sorts of bad stuff from your own lan. After creating a user on your device by running useroobe.dll they have admin perms and usually do a lot of bad stuff.
Hackers typically use Mimikatz to extract credentials, which essentially involves a memory dump of lsass.exe and extracting the credentials from the dump. C:\Users by default has Everyone group permissions, and Public folders have special permissions, 
so if a hacker wants to stay hidden, they’ll operate from there. That typically means accessing your desktop. So if you share a screenshot of your desktop — with a unique background — they can identify and track you, i.e., associate that machine with your online username.
That also means that any icon on your desktop, taskbar, or context menu is potentially accessible to the hacker. Once they’re in, they can use Juicy Potato or a similar “potato” exploit to gain SYSTEM privileges.
If you offend these assholes, they may hide a trojan in Recycle Bin of the last drive and your router. So if you wipe all your drives, it’ll copy itself back from the router. If you reset the router, it’ll copy itself back from the Recycle Bin to the router.
They may also try to determine what mouse you use and infect it with a macro that continuously downloads the latest payload — probably from a URL containing xss in its name. They’ll leave multiple backdoors to access your machine: a trojan, VNC server, RDP shadow rule, SSH, Telnet, AnyDesk, etc.
If they add you to their Azure environment, or use any other c control app, they can use the Azure dashboard to push policies to all computers under their control or use them for DDoS attacks.

This script is designed to be added to official windows iso, and prevent this bullshit from even starting. Essentially it runs a script after you reach desktop, which removes permissions from useroobe.dll, removes prebuilt user and disables and stops secondary logon. 
So, nobody can create new users, which means hackers have zero permissions on your pc, so anything they would normally do is blocked. Add this to a windows installation flashdrive, install windows, and surf without fear of anything. No need to escape to Linux. 
Windows is a safe enviroment with this script. Note this script is designed to protect you from baddies, not protect you if you're a baddie yourself.

