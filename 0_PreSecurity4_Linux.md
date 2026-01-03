Linux Fundamentals
==================================================
https://tryhackme.com/room/linuxfundamentalspart2

```
ssh tryhackme@10.64.186.52
```

touch - create a file
file - determine a type of file

/etc
-----

This root directory is one of the most important root directories on your system. The etc folder (short for etcetera) is a commonplace location to store system files that are used by your operating system. 

For example, the sudoers file highlighted in the screenshot below contains a list of the users & groups that have permission to run sudo or a set of commands as the root user.

Also highlighted below are the "passwd" and "shadow" files. These two files are special for Linux as they show how your system stores the passwords for each user in encrypted formatting called sha512.\

/var
-----

The "/var" directory, with "var" being short for variable data,  is one of the main root folders found on a Linux install. This folder stores data that is frequently accessed or written by services or applications running on the system. 
For example, log files from running services and applications are written here (/var/log), or other data that is not necessarily associated with a specific user (i.e., databases and the like).

/root
------

Unlike the /home directory, the /root folder is actually the home for the "root" system user. There isn't anything more to this folder other than just understanding that this is the home directory for the "root" user. 
But, it is worth a mention as the logical presumption is that this user would have their data in a directory such as "/home/root" by default.  

/tmp
-----

This is a unique root directory found on a Linux install. Short for "temporary", the /tmp directory is volatile and is used to store data that is only needed to be accessed once or twice. 
Similar to the memory on your computer, once the computer is restarted, the contents of this folder are cleared out.

What's useful for us in pentesting is that any user can write to this folder by default. Meaning once we have access to a machine, it serves as a good place to store things like our enumeration scripts.

Terminal Text Editors
======================
- echo with > or >>
- nano

Downloading Files (Wget)
========================
```
wget https://assets.tryhackme.com/additional/linux-fundamentals/part3/myfile.txt
```

Transferring Files From Your Host - SCP (SSH)
=============================================
- secure copy

- secure copy of the important.txt file to the 192.168.1.30 machine, ubuntu user. rename important.txt t transferred.txt.
  ```
  scp important.txt ubuntu@192.168.1.30:/home/ubuntu/transferred.txt
  ```

- secure copy from the 192.168.1.30 machine, ubuntu user, rename documents.txt to notes.txt
  ```
  scp ubuntu@192.168.1.30:/home/ubuntu/documents.txt notes.txt 
  ```

Serving Files From Your Host - WEB
==================================
- HTTPServer - in python
  - This module turns your computer into a quick and easy web server that you can use to serve your own files, where they can then be downloaded by another computing using commands such as curl and wget.
  ```
  python3 -m  http.server
  ```
  Keep the server running, open new terminal, and write:
  ```
  wget http://10.66.145.208:8000/myfile
  ```

  Updog webserver - https://github.com/sc0tfree/updog

Processes
=========
- managed by Kernel
- identified with PID
- ps: get running processes (ps aux for other users' -, system processes, etc.
- top: real-time running processes
 
Managing Processes
------------------
```
kill 1337
```
kills the process with the 1337 PID
  
- SIGTERM - Kill the process, but allow it to do some cleanup tasks beforehand
- SIGKILL - Kill the process - doesn't do any cleanup after the fact
- SIGSTOP - Stop/suspend a process

Namespaces
----------
- The Operating System (OS) uses namespaces to ultimately split up the resources available on the computer to (such as CPU, RAM and priority) processes
- Namespaces are great for security as it is a way of isolating processes from another -- only those that are in the same namespace will be able to see each other.
- Any program or piece of software that we want to start will start as what's known as a child process of systemd. This means that it is controlled by systemd, but will run as its own process (although sharing the resources from systemd) to make it easier for us to identify and the likes.
```
systemctl [option] [service]
```
interact with the systemd process/daemon
- Start
- Stop
- Enable
- Disable

- backgrounding the process:
  ```
  echo "HI!" # run in foreground
  echo "HI!" & # run in background
  ```
  - Ctrl + Z: backgrounding during the run
  -  fg: foregrounding the process
    
-  crontabs:
   - started during boot, responsible for facilitating and managing cron jobs
   - A crontab is simply a special file with formatting that is recognised by the cron process to execute each line step-by-step. Crontabs require 6 specific values:
   - https://crontab-generator.org/
   - https://crontab.guru/
   - crontab -e: edit crontab

Introducing Packages & Software Repos
=====================================
- apt: repo for sw sharing
- add-apt-repository
- dpkg: package installer
- when adding software, the integrity of what we download is guaranteed by the use of what is called GPG (Gnu Privacy Guard) keys
  - to start, we need to add the GPG key for the developers of Sublime Text 3.
