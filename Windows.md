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
- Encryption ( Encryption File System or EFS )
