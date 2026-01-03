Active Directory Basics - Introduction
=======================================
- It simplifies the management of devices and users within a corporate environment.
- **Windows domain** = a group of users and computers under the administration of a given business. 
The main idea behind a domain is to centralise the administration of common components of a Windows computer network in a single repository called **Active Directory (AD)**. The server that runs the Active Directory services is known as a **Domain Controller (DC)**.

Windows Domains
----------------
The main advantages of having a configured Windows domain are:
- **Centralised identity management:** All users across the network can be configured from Active Directory with minimum effort.
- **Managing security policies:** You can configure security policies directly from Active Directory and apply them to users and computers across the network as needed.

Active Directory
-----------------
**Active Directory Domain Service (AD DS)** - service that acts as a catalogue that holds the information of all of the "objects" that exist on your network
- users, groups, machines, printers, shares, ...

Objects within the Active Directory:
- Users
  - security principals: they can be authenticated by the domain and can be assigned privileges over resources like files or printers
  - people or services (like IIS or MSSQL) are users
- Machines
  -  for every computer that joins the Active Directory domain, a machine object will be created
  -  also considered "security principals" and are assigned an account just as any regular user. This account has somewhat limited rights within the domain itself.
  -  The machine accounts themselves are local administrators on the assigned computer, they are generally not supposed to be accessed by anyone except the computer itself, but as with any other account, if you have the password, you can use it to log in.
  -  Note: Machine Account passwords are automatically rotated out and are generally comprised of 120 random characters.
  -  The machine account name = the computer's name followed by a dollar sign. For example, a machine named DC01 will have a machine account called DC01$.
 
-  Security Groups
  -   also considered security principals and, therefore, can have privileges over resources on the network.
  -   Groups can have both users and machines as members. If needed, groups can include other groups as well.
  -   Several groups are created by default in a domain that can be used to grant specific privileges to users:
    
   |Security Group      |	Description                                                                                                                                               |
   | ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
   | Domain Admins	    | Users of this group have administrative privileges over the entire domain. By default, they can administer any computer on the domain, including the DCs. |
   | Server Operators	  | Users in this group can administer Domain Controllers. They cannot change any administrative group memberships.                                           |
   | Backup Operators	  | Users in this group are allowed to access any file, ignoring their permissions. They are used to perform backups of data on computers.                    |
   | Account Operators  |	Users in this group can create or modify other accounts in the domain.                                                                                    |
   | Domain Users       |	Includes all existing user accounts in the domain.                                                                                                        |
   | Domain Computers	  | Includes all existing computers in the domain.                                                                                                            | 
   | Domain Controllers	| Includes all existing DCs on the domain.                                                                                                                  |
   | other              | see https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups                                                     |

Active Directory Users and Computers
- log in to the Domain Controller and run "Active Directory Users and Computers" from the start menu
- **Organizational Units (OUs)**:
  - container objects that allow you to classify users and machines
  - a user can only be a part of a single OU at a time

- default containers:
  - **Builtin:** Contains default groups available to any Windows host.
  - **Computers:** Any machine joining the network will be put here by default. You can move them if needed.
  - **Domain Controllers:** Default OU that contains the DCs in your network.
  - **Users:** Default users and groups that apply to a domain-wide context.
  - **Managed Service Accounts:** Holds accounts used by services in your Windows domain.

Security Groups vs OUs
- **Organizational Units (OUs)** are handy for applying policies to users and computers, which include specific configurations that pertain to sets of users depending on their particular role in the enterprise. Remember, a user can only be a member of a single OU at a time, as it wouldn't make sense to try to apply two different sets of policies to a single user.
- **Security Groups**, on the other hand, are used to grant permissions over resources. For example, you will use groups if you want to allow some users to access a shared folder or network printer. A user can be a part of many groups, which is needed to grant access to multiple resources.

- TODO:
- Domain Admins
- TOM-PC$
- Organizational Units




