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

Start menu > msconfig
Microsoft advises using Task Manager (taskmgr) to manage (enable/disable) startup items. The System Configuration utility is NOT a startup management program. 

In Windows Server: Windows servers handle startup applications differently than Windows client systems. Unlike Windows 10 or 11, you will not see startup programs in Task Manager or in the Startup tab of msconfig.
On these Windows server machines, the only reliable way to view user-level startup items is through the Startup folder itself. You can access it by pressing Win + R, which opens the Run Dialog, typing shell:startup, and then pressing Enter. 

PsShutdown is a Sysinternals command-line utility used to shut down, restart, log off, lock, or put a Windows system to sleep, either locally or remotely.

Control Panel: control.exe












