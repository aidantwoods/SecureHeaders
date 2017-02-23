Before the real introduction, the following should be taken as a good implementation examples (SecureHeaders will tell you if you're missing policies, or if they look questionable).

These aren't good because they're short, rather they make use of some key browser security features (namely [HSTS](hsts) and [CSP](csp))

```php
$headers = new SecureHeaders();
$headers->hsts();
$headers->csp('default', 'self');
$headers->csp('script', 'https://my.cdn.org');
$headers->apply();
```

Here's an even better one (but don't copy paste it into production code unless you understand what HSTS preloading is):
```php
$headers = new SecureHeaders();
$headers->strictMode();
$headers->cspNonce('script');
$headers->apply();
```
As an aside to that warning, do take a look at [`->safeMode`](safeMode) if you're worried about breaking something with headers (or don't plan on reading the documentation before typing).

For more on these examples, [see below](#examples).

# Getting Started

To get started with SecureHeaders, you need only create an instance of the class and call [`->apply`](apply) before your first byte of output. If you're not sure where, or what that is then you can tell SecureHeaders to set all the headers for you when output is generated, using [`->applyOnOutput`](applyOnOutput).

The former option is simply the following two lines of code:
```php
$headers = new SecureHeaders();
$headers->apply();
```
The latter could be achieved by slightly rewriting the second line.

Okay, so what did that do exactly?

## Automatic Behaviour
The following details behaviour that is automatically applied to every instance of SecureHeaders (unless these settings are modified).

### Added Headers
When `->apply` was called, SecureHeaders analysed all the headers already loaded in PHPs internal list. 

As part of this process, the following headers will be sent. This provided they don't already have values (and are not explicitly removed using [`->removeHeader`](removeHeader)).

```
X-Content-Type-Options:nosniff
X-Frame-Options:Deny
X-XSS-Protection:1; mode=block
```

### Errors and Warnings
SecureHeaders will also note that neither a Content-Security-Policy has been defined, nor an HSTS policy. The following warnings will be generated as a result of this:
> **Warning:** Missing security header: 'Strict-Transport-Security'

> **Warning:** Missing security header: 'Content-Security-Policy'


### Removed Headers

Additionally, some headers will be removed. In particular the header `X-Powered-By` (often sent by default) will be removed by SecureHeaders. This header is removed because it often leaks quite detailed version information about the current PHP installation. While certainly not a vulnerability itself, this header can aid an attacker in profiling the system (let's not give out this information for free).

It is also advisable that the `Server` header is removed, because it leaks much of the same information. SecureHeaders will attempt to remove it. However, it is unlikely PHP will be able to affect this header if the underlying web server is sending it. So this header should be configured manually in the web server.


### Protected Cookies

If any cookies have been set at any time before `->apply()` is
called(, or at any time before the first byte of output if `->applyOnOutput()` is set).

Consider the following as an example.
```php
<?php
$headers = new SecureHeaders();
$headers->applyOnOutput();

setcookie('auth', generateSuperSecretAuthenticationString());
?>
<html>
<body>
    <h1>Account Settings</h1>
...
</body>
</html>
```

Even though in the current PHP configuration, cookie flags `Secure` and `HTTPOnly` do **not** default to on, the end result of the `Set-Cookie` header will be
```
Set-Cookie:auth=supersecretauthenticationstring; secure; HttpOnly
```

These flags were inserted by SecureHeaders because the cookie name contained the substring `auth`. Of course if that was a bad assumption, you can correct SecureHeaders' behaviour ([`->protectedCookie`](protectedCookie)), conversely you can tell SecureHeaders about some of your cookies that have less obvious names – but may need protecting in case of accidental missing flags.

# More

There's quite a bit more to cover: [CSP](csp), [HSTS](hsts), [HPKP](hpkp), and much more – just check out the sidebar and have a browse through the function list to take a look.

### Examples

To cover the initial examples in a bit more detail:
#### Example 1
```php
$headers = new SecureHeaders();
$headers->hsts();
$headers->csp('default', 'self');
$headers->csp('script', 'https://my.cdn.org');
$headers->apply();
```
Here, [`->hsts`](hsts) with no arguments will deploy Strict-Transport-Security with a one year duration.

The lines calling [`->csp`](csp) will add `'self'` as a whitelisted source to `default-src` (note the use of [friendly directive](friendly_directives_and_sources#directives), and [friendly source](friendly_directives_and_sources#sources) names here to save a little typing).

#### Example 2
```php
$headers = new SecureHeaders();
$headers->strictMode();
$headers->cspNonce('script');
$headers->apply();
```
Here, [`->strictMode`](strictMode) is used. Strict mode will deploy Strict-Transport-Security with a one year duration, and `includeSubDomains` and `preload` flags. (You'll still have to [manually submit](https://hstspreload.appspot.com/) your domain to become preloaded though).

Strict mode will also opportunistically enable `'strict-dynamic'` in CSP – which disables the whitelist in CSP3 compliant browsers for the `script-src` directive in favour of hashes and nonces.

The line calling [`->cspNonce`](cspNonce) simply generates a nonce for the `script-src` directive. Note that this nonce can be retrieved at any time by calling the same function with `script-src`, or one of its [friendly names](friendly_directives_and_sources) (as above). By default `->cspNonce` will only generate a new nonce for the directive if one does not already exist, and will always return a nonce for the directive specified (whether it be newly generated, or an already existing nonce).
