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

