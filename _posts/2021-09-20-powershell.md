---
layout: post
title: PowerShell - CheetSheat
description: "PowerShell - CheetSheat"
tags: [Windows,PowerShell]
---

### No interactivo, ejecutar powershell

```
powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File file.ps1
```

### ¿Es de 64 bits?

```
[environment]::Is64BitOperatingSystem
```

### Get-SmbShareAccess

obtiene objetos que representan los derechos que se han otorgado a los principios de seguridad para acceder al recurso compartido del bloque de mensajes del servidor (SMB).

```
Get-SmbShareAccess -Name <share>
```

### Desactivar Windows Defender

```
Set-MpPreference -DisableRealtimeMonitoring $true
```

### Desinstalar Windows Defender

```
Uninstall-WindowsFeature -Name Windows-Defender
```

### Teclado español peru

```
Set-WinUserLanguageList -LanguageList  es-PE -Force
```

### Ver distribucion del taclado

```
Get-WinUserLanguageList
```

### Duerme x segundos

```
Start-Sleep -Seconds <number>
```

### Reiniciar el sistema

```
Restart-Computer
```

### Limpiar terminal

```
Clear-Host
```

### Nombre del equipo

```
$env:computername
```

### Apagar el equipo

```
shutdown -s -t 0
```
