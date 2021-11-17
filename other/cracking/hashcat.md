# Hashcat

### Tool <a href="tool" id="tool"></a>

{% embed url="https://github.com/hashcat/hashcat" %}
Hashcat - World's fastest and most advanced password recovery utility
{% endembed %}

{% embed url="https://hashcat.net/wiki/doku.php?id=example_hashes" %}
Generic hash types
{% endembed %}

### Parameters <a href="parameters" id="parameters"></a>

```
-m: Mode (hash type)
-a: Attack type
    0 = Straight (dictionary)
    1 = Combination
    2 = Toggle-Case
    3 = Brute-force
    4 = Permutation
    5 = Table-Lookup
    8 = Prince
-o: Output (if you want it to be saved in a txt)
```

### Attack examples <a href="attack-examples" id="attack-examples"></a>

```bash
#Dictionary attack
hashcat -m 1800 -a 0 shadow.txt /usr/share/wordlists/rockyou.txt​

#Brute-force attack
hashcat -m 1800 -a 3 shadow.txt
```

### Complete guide about hashcat use (in spanish) <a href="complete-guide-about-hashcat-use-in-spanish" id="complete-guide-about-hashcat-use-in-spanish"></a>

{% embed url="https://jesux.es/cracking/passwords-cracking/" %}
Guia: Introduccion al Password Crackingó
{% endembed %}
