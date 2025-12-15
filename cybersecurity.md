Offensive Security Intro
========================
https://tryhackme.com/room/offensivesecurityintro
Gobuster: command-line application to brute-force the Website (https://github.com/OJ/gobuster)
```
gobuster -u http://fakebank.thm -w wordlist.txt dir
```
In the command above, -u is used to state the website we're scanning, -w takes a list of words to iterate through to find hidden pages.

