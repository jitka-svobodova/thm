Windows Fundamentals 1
=======================
The file system
----------------
The file system used in modern versions of  Windows  is the New Technology File System or simply  NTFS .
Before NTFS, there was  FAT16/FAT32 (File Allocation Table) and HPFS (High Performance File System). 

You still see FAT partitions in use today. For example, you typically see FAT partitions in USB devices, MicroSD cards, etc.  but traditionally not on personal Windows computers/laptops or Windows servers.

NTFS is known as a journaling file system. In case of a failure, the file system can automatically repair the folders/files on disk using information stored in a log file. This function is not possible with FAT.   
NTFS addresses many of the limitations of the previous file systems; such as: 
- Supports files larger than 4GB
- Set specific permissions on folders and files
- Folder and file compression
- Encryption (Encryption File System or EFS)

| Permission             | Meaning for Folders                                                                                               | Meaning for Files                                                                     |
| :--------------------- |:----------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------------------------------------------|
| Read                   | Permits viewing and listing of files and subfolders                                                               | Permits viewing or accessing of the file's contents                                   |
| Write                  | Permits adding of files and subfolders                                                                            | Permits writing to a file                                                             |
| Read & Execute         | Permits viewing and listing of files and subfolders as well as executing of files; inherited by files and folders | Permits viewing and accessing of the file's contents as well as executing of the file |
| List Folder Contents   | Permits viewing and listing of files and subfolders as well as executing of files; inherited by folders only      | N/A                                                                                   |
| Modify                 | Permits reading and writing of files and subfolders; allows deletion of the folder                                | Permits reading and writing of the file; allows deletion of the file                  |
| Full Control           | Permits reading, writing, changing, and deleting of files and subfolders                                          | Permits reading, writing, changing and deleting of the file                           |

Refer to the Microsoft documentation to get a better understanding of the NTFS permissions for  Special Permissions.

Another feature of NTFS is Alternate Data Streams (ADS) - a file attribute specific to Windows NTFS  (New Technology File System).
Every file has at least one data stream ( $DATA ), and ADS allows files to contain more than one stream of data. Natively Window Explorer doesn't display ADS to the user. There are 3rd party executables that can be used to view this data, PowerShell also gives you the ability to view ADS for files. We will cover how you can use PowerShell to view any ADS for any files in the Windows PowerShell room.
**From a security perspective, malware writers have used ADS to hide data.** Not all its uses are malicious. For example, when you download a file from the Internet, there are identifiers written to ADS to identify that the file was downloaded from the Internet.

To learn more:
--------------
https://www.malwarebytes.com/blog/101/2015/07/introduction-to-alternate-data-streams
https://tryhackme.com/room/adventofcyber2 day 21


Windows/system32
-----------------
%windir% - the system  environment variable for the Windows directory

The System32 folder holds the important files that are critical for the operating system. Many of the tools that will be covered in the Windows Fundamentals series reside within the System32 folder. 
https://www.howtogeek.com/346997/what-is-the-system32-directory-and-why-you-shouldnt-delete-it/

User Accounts
--------------
Local User and Group Management: Right-click on the Start Menu and click Run. Type lusrmgr.msc

If you click on Add someone else to this PC from Other users, it will open Local Users and Management. 

User Account Control (UAC)
--------------------------
- UAC (by default) doesn't apply for the built-in local administrator account.
- When a user with an account type of administrator logs into a system, the current session doesn't run with elevated permissions. When an operation requiring higher-level privileges needs to execute, the user will be prompted to confirm if they permit the operation to run.
https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works

Task manager
------------
https://www.howtogeek.com/405806/windows-task-manager-the-complete-guide/

https://tryhackme.com/jr/btwindowsinternals

Windows Fundamentals 2
======================
System Configuration
--------------------
The System Configuration utility (MSConfig) is for advanced troubleshooting, and its main purpose is to help diagnose startup issues. 

https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/system-configuration-utility-troubleshoot-configuration-errors

**Start menu > msconfig**

Microsoft advises using Task Manager (taskmgr) to manage (enable/disable) startup items. The System Configuration utility is NOT a startup management program. 

In Windows Server: Windows servers handle startup applications differently than Windows client systems. Unlike Windows 10 or 11, you will not see startup programs in Task Manager or in the Startup tab of msconfig.
On these Windows server machines, the only reliable way to view user-level startup items is through the Startup folder itself. You can access it by pressing Win + R, which opens the Run Dialog, typing shell:startup, and then pressing Enter. 

PsShutdown is a Sysinternals command-line utility used to shut down, restart, log off, lock, or put a Windows system to sleep, either locally or remotely.

Control Panel: control.exe

Change UAC Settings
-------------------
This slider has four security levels, each of which controls how Windows alerts you when apps or users try to make changes at the system level. They fall into four standard categories as explained below:
- Always notify: This is the highest security. Windows notifies you whenever any apps or you yourself try to make changes, and the desktop dims (Secure Desktop).
- Notify for apps: Windows notifies only when apps try to make changes, but not when you change Windows settings. This option is enabled by default.
- Notify without dimming: Same as above (Notify for apps), but this time the screen does not dim. 
- Never notify: Notifications are turned off. Windows won’t warn you about any changes made by you or any apps. 

Computer Management
--------------------
- Task Scheduler
- Event Viewer: view events that have occurred on the computer.
  - Windows logs
- Shared folders
- WMI Control configures and controls the Windows Management Instrumentation (WMI) service.
  - Per Wikipedia, "WMI allows scripting languages (such as VBScript or Windows PowerShell) to manage Microsoft Windows personal computers and servers, both locally and remotely. Microsoft also provides a command-line interface to WMI called Windows Management Instrumentation Command-line (WMIC)."
  - Note: The WMIC tool is deprecated in Windows 10, version 21H1. Windows PowerShell supersedes this tool for WMI.

System Information
------------------
- HW Summary, Componente, Env Variables...

Resource Monitor
----------------
- Network: TCP, ports, ...

Command Prompt
--------------
https://ss64.com/nt/
- hostname
- whoami
- ipconfig
- help: ipconfig /?
- cls
- netstat
- net, net help, net user, net help user

Registry Editor
---------------
The Windows Registry (per Microsoft) is a central hierarchical database used to store information necessary to configure the system for one or more users, applications, and hardware devices.
https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/windows-registry-advanced-users

Windows Fundamentals 3
======================
Windows Update
--------------
- 2nd Tuesday of each month = patch Tuesday
- https://msrc.microsoft.com/update-guide
- Windows Update is located in Settings
```
control /name Microsoft.WindowsUpdate
```
https://support.microsoft.com/en-us/windows/windows-update-faq-8a903416-6f45-0718-f5c7-375e92dddeb2

Windows Security
----------------
- Virus & threat protection
- Firewall & network protection
- App & browser control
- Device security

Virus & threat protection
--------------------------
is divided into two parts:
- Current threats
- Virus & threat protection settings

Firewall
---------
"Traffic flows into and out of devices via what we call ports. A firewall is what controls what is - and more importantly isn't - allowed to pass through those ports. You can think of it like a security guard standing at the door, checking the ID of everything that tries to enter or exit".

- command to open the Windows Defender Firewall is WF.msc
- https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure

App & browser control
----------------------
"Microsoft Defender SmartScreen protects against phishing or malware websites and applications, and the downloading of potentially malicious files".
https://feedback.smartscreen.microsoft.com/smartscreenfaq.aspx

Device security
---------------
Core isolation
- Memory Integrity - Prevents attacks from inserting malicious code into high-security processes.

Security processor
- Trusted platform module (TPM)

BitLocker
----------
BitLocker Drive Encryption is a data protection feature that integrates with the operating system and addresses the threats of data theft or exposure from lost, stolen, or inappropriately decommissioned computers.

On devices with TPM installed, BitLocker offers the best protection.

Per Microsoft, "BitLocker provides the most protection when used with a Trusted Platform Module (TPM) version 1.2 or later. The TPM is a hardware component installed in many newer computers by the computer manufacturers. It works with BitLocker to help protect user data and to ensure that a computer has not been tampered with while the system was offline".

https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/

We should use a removable drive on systems without a TPM version 1.2 or later. What does this removable drive contain? - startup key

Volume Shadow Copy Service
---------------------------
Per Microsoft, the Volume Shadow Copy Service (VSS) coordinates the required actions to create a consistent shadow copy (also known as a snapshot or a point-in-time copy) of the data that is to be backed up. 
If VSS is enabled (System Protection turned on), you can perform the following tasks from within advanced system settings. 
- Create a restore point
- Perform system restore
- Configure restore settings
- Delete restore points

- From a security perspective, malware writers know of this Windows feature and write code in their malware to look for these files and delete them. Doing so makes it impossible to recover from a ransomware attack unless you have an offline/off-site backup.

- Bonus: If you wish to interact hands-on with VSS, I suggest exploring Day 23 of Advent of Cyber 2. https://tryhackme.com/room/adventofcyber2

- Antimalware Scan Interface https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal
- Credential Guard https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure?tabs=intune
- Windows 10 Hello https://support.microsoft.com/en-us/windows/configure-windows-hello-dae28983-8242-bb2a-d3d1-87c9d265a5f0#:~:text=Windows%2010,in%20with%20just%20your%20PIN.
- CSO Online - The best new Windows 10 security features https://www.csoonline.com/article/564531/the-best-new-windows-10-security-features.html

- Note: Attackers use built-in Windows tools and utilities in an attempt to go undetected within the victim environment.  This tactic is known as Living Off The Land. Refer to the following resource here to learn more about this.  https://lolbas-project.github.io/

- 


