# Insecure Direct Object Reference (IDOR)

### Change file extension

Try to change the extension of the endpoint that you have.

```bash
#Endpoint found
/users/password -> 401

#Endpoints to test
/users/password.json
/users/password.xml
```

### Convert request body

Convert the body of the request to array or to include a json on it.

```bash
#Original body
{"id":1}

#Bypasses
{"id":[1]}
{"id":{"id":1}}
```

### Test wildcards

Change the identifier of the request to a wildcard.

```bash
#Original request
/api/v1/userlist/user1

#Wildcard bypasses
/api/v1/userlist/*
```

### Check another version

Many API endpoints expose the version in the request, try to change it to use another older.

```bash
#Original request
/api/v3/user/user3

#Changed version of the same endpoint
/api/v2/user/user3
/api/v1/user/user3
```

### References

{% embed url="https://portswigger.net/bappstore/f9bbac8c4acf4aefa4d7dc92a991af2f" %}
Burp Suite extension aimed at helping the penetration tester to detect authorization vulnerabilities
{% endembed %}

{% embed url="https://portswigger.net/bappstore/f89f2837c22c4ab4b772f31522647ed8" %}
Burp Suite extension that automatically repeats requests, with replacement rules and response diffing
{% endembed %}
