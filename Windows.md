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























