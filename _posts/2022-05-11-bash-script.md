---
layout: post
title: Bash Scripting
tags: [linux, bash]
description: linux scripting tricks
---

### For
```bash
> for ip in $(seq 1 10); do echo 192.168.100.$ip; done
> for ip in {1...10}; do echo 192.168.100.$ip; done
```

## AWK
### Filter by argument
```bash
> cat /etc/passwd | awk -F ":" '{print $1}'
```

##  Cut
### Filter by argument
```bash
> cat /etc/passwd | cut -d ":" -f 1
```

<embed src="https://www.uv.mx/pozarica/caa-conta/files/2016/02/REGULAR-AND-IRREGULAR-VERBS.pdf" type="application/pdf" width="300px" height="400px" />

<iframe src="https://prezi.com/p/embed/g-4-lbimbc9c/" id="iframe_container" frameborder="0" webkitallowfullscreen="" mozallowfullscreen="" allowfullscreen="" allow="autoplay; fullscreen" height="315" width="560"></iframe>
