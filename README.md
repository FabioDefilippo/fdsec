# fdsec
Tool to improve security in Windows!

## What is it?
These tools help You check for a malware infection through common behaviors!

## How to use theme?
1. Download these codes (I don't take responsibility for loading the binaries yet, maybe later) and paste them in your C# projects in Visual Studio;
2. In "Security-Check" Project, Add reference (Project/Add reference) "System.Management" and "System.ServiceProcess";
3. Compile Projects separately;
4. Run ollydbg.exe and then security-check.exe with <strong>administrator privileges</strong>;

## And Then?
This tool will shutdown the OS based on at least one of these conditions:

- ollydbg.exe process killed (malwares kill debugger softwares at the execution);
- Windows Defender process/service (malwares kill security and important services);
- Windows Firewall service (as above);
- Shadow copies service (malwares stop backups routine);
- Windows update service;
- Windows security center;
- delete backups and Shadow copies command lines (malwares delete backups to avoid recovery files);
- a process with administrator privileges run from a subdirectory in AppData path (malwares need have admin privileges to works better);

security-check.exe will shutdown the System to stop the infection!

## WARNING:
- If You do not use Windows Defender or Windows Firewall, delete or comment "msmpeng.exe" or "MpsSvc" block of code or replace names with your AV!
- You can rename "ollydbg" project to another name, but You must change the name in "Security-Check" project!
- this code check other services, please verify in code which ones interest you and run them all in Your Windows!
