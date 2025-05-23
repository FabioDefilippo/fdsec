# fdsec
Some security tools!

## What is it?
These tools help You check for a malware infection through common behaviors!

## How to use theme?
1. Download these codes (I don't take responsibility for loading the binaries yet, maybe later);
2. In Security-Check Project, Add reference (Project/Add reference) "System.Management" and "System.ServiceProcess";
3. Compile Projects separately;
4. Run ollydbg.exe and then security-check.exe;

## And Then?
If a malware will kill ollydbg.exe process, Windows Defender process or Windows Firewall service, security-check.exe will shutdown the System to stop the infection!

## WARNING:
If You do not use Windows Defender or Windows Firewall, delete or comment "msmpeng.exe" or "MpsSvc" block of code or replace names with your AV!
