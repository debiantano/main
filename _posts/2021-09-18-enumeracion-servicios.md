---
layout: post
title: Servicios
tags: [CheetSheat]
description: "Servicios"
---

## Samba

### smbmap

```
smbmap -H <ip> -r /share/share2
smbmap -H <ip> --download /share/share2/file
smbmap -H <ip> -d <domain> -u <user> -p <password>
```

### smbclient

```
smbclient //<ip>/share -U <domain>\\<user>%<password>
```

### psexec

```
psexec.py <domain>/<user>@<ip>
```

----
