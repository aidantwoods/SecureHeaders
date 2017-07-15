## Description
```php
void auto ( [ int $mode = SecureHeaders::AUTO_ALL ] )
```

`->auto()` is used to enable or disable certain automatically applied header functions

If unconfigured, the default setting for `->auto` is `SecureHeaders::AUTO_ALL`.

## Parameters
### mode
`mode` accepts one or more of the following constants. Multiple constants may be specified by combination using [bitwise operators](https://secure.php.net/manual/language.operators.bitwise.php)

## Valid Constants
### AUTO_ALL
```php
SecureHeaders::AUTO_ALL = SecureHeaders::AUTO_ADD
                        | SecureHeaders::AUTO_REMOVE
                        | SecureHeaders::AUTO_COOKIE_SECURE
                        | SecureHeaders::AUTO_COOKIE_HTTPONLY
```
`AUTO_ALL` will enable everything listed below.

### AUTO_ADD
```php
SecureHeaders::AUTO_ADD
```
`AUTO_ADD` will make the following [header proposals](header-proposals):
```
X-Content-Type-Options:nosniff
X-Frame-Options:Deny
X-XSS-Protection:1; mode=block
```

**A note on forgoing this setting:** You have the option to disable automatically added headers outright, but its in almost all cases a bad idea (you may benefit from changes to this list across updates). Instead, if you want to make changes, manually overwrite these headers with [`->header`](header), or manually remove them [`->removeHeader`](removeHeader).

### AUTO_REMOVE
```php
SecureHeaders::AUTO_REMOVE
```
`AUTO_REMOVE` will cause certain headers that disclose internal server information, to be automatically removed. If set, the following headers will be automatically staged for removal:
```
Server
X-Powered-By
```
Note that while SecureHeaders will instruct PHP to remove the `Server` header, it is unlikely that PHP will be able to honour the request. This headers should ideally be removed by configuring the underlying webserver.

### AUTO_COOKIE_SECURE
```php
SecureHeaders::AUTO_COOKIE_SECURE
```
`AUTO_COOKIE_SECURE` will ensure that cookies considered [protected](protectedCookie), will have the `Secure` flag when they are sent to the users browser. This will ensure that the cookie is only ever sent by the user over a secure connection.

**A note on forgoing this setting:** If you ~~can't serve your site securely~~ aren't using [LetsEncrypt](https://letsencrypt.org/) for now, then disable this. Otherwise corrections to incorrectly secured cookies (is there such a thing), or additions can be made using [`protectedCookie`](protectedCookie).

### AUTO_COOKIE_HTTPONLY
```php
SecureHeaders::AUTO_COOKIE_HTTPONLY
```
`AUTO_COOKIE_HTTPONLY` will ensure that cookies considered [protected](protectedCookie), will have the `HttpOnly` flag when they are sent to the users browser. This will ensure that the cookie is not accessible by JavaScript. This is a good failsafe to ensure that even if the web application contains an XSS vulnerability, then the protected cookie will not be accessible to an attacker who can inject malicious code.

**A note on forgoing this setting:** Corrections to incorrectly marking cookies as HttpOnly, or additions to the cookies that are automatically marked can be made using [`protectedCookie`](protectedCookie).