# SecureHeaders
A PHP class aiming to make the use of browser security features more accessible, while allowing developers to safely experiment with these features to ensure they are configured correctly.

The project aims help increase the overall security of an application in-which it runs within. 

Sometimes this is most appropriately applied through feedback. SecureHeaders will issue warnings (`level E_USER_WARNING`) and notices (`level E_USER_NOTICE`) at runtime when it notices something is wrong. 

In some cases, correcting insecure behaviour is best done pro-actively. SecureHeaders will modify or add headers (where safe to do so). (This can of course be granularly controlled, or outright disabled). This includes adding security flags to cookies with certain keywords in their names in an effort to protect session data. And also by adding missing security headers to automatically enable client browser security features.

## Development Notice
This project is currently under initial development, so there is the potential for non-backwards compatible changes etc.. That said, bug reports are still welcome from anyone who wants to test it out.

## Features
* Add/remove and manage headers easily
* Build a Content Security Policy, or combine multiple together
* Correct cookie flags on already set cookies to add httpOnly and secure flags, (if the cookies appear to be session related)
* Safe mode prevents accidential self-DOS when using HSTS, or HPKP
* Receive warnings about missing security headers (`level E_USER_WARNING`)

## Basic Example
An 'out-of-the-box' example is as follows:
```php
$headers = new SecureHeaders();
$headers->done();
```

With such code, the following will occur:
* Warnings will be issued (`E_USER_WARNING`)

  ```
  Warning: Missing security header: 'Strict-Transport-Security'
  Warning: Missing security header: 'Content-Security-Policy'
  ```
* The following headers will be automatically added

  ```
  X-Content-Type-Options:nosniff
  X-Frame-Options:Deny
  X-XSS-Protection:1; mode=block
  ```

Additionally, if any cookies have been set (at any time before `->done()` is called) e.g.
```php
setcookie('auth', 'supersecretauthenticationstring');

$headers = new SecureHeaders();
$headers->done();
```
Even though in the current PHP configuration, cookie flags `Secure` and `HTTPOnly` do **not** default to on, the end result of the `Set-Cookie` header will be
```
Set-Cookie:auth=supersecretauthenticationstring; secure; HttpOnly
```

This is because the cookie name contains a keyword substring (`auth` in this case). When SecureHeaders sees this it will pro-actively inject the `Secure` and `HTTPOnly` flags into the cookie, in an effort to correct an error that could lead to session hijacking.


## More on Usage
*(section nowhere close to complete)*

e.g. the following will combine `$baseCSP` with `$csp` to create an overall Content-Security-Policy.
```php
$headers = new SecureHeaders();

$baseCSP = array(
  "default-src" => ["'self'"]
);
$headers->csp($baseCSP);

$csp = array(
  "frame-src" => ["https://www.example.com/"],
  "style-src" => ["'nonce-$style_nonce'"],
  "script-src" => ["'nonce-$script_nonce'"]
);

$headers->csp($csp);

$headers->done();
```

The `SecureHeaders` class can also be extended, so that custom settings can be applied on all instances of the extension.
e.g. `$baseCSP` on all pages.

```php
class CustomSecureHeaders extends SecureHeaders{
    public function __construct()
    {
      $this->csp($this->base);
    }
    private $base = array(
      "default-src" => ["'self'"],
      "style-src" => [
        "'self'",
        "https://fonts.googleapis.com/",
        "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/"
      ]
    );
}
```

```php
$headers = new CustomSecureHeaders();

$pageSpecificCSP = array(
  "frame-src" => ["https://www.example.com/"],
  "style-src" => ["'nonce-$style_nonce'"],
  "script-src" => ["'nonce-$script_nonce'"]
);

$headers->csp($pageSpecificCSP);

$headers->done();
```

etc...

This readme is incomplete, please refer to the source, or the (non-exhaustive) example file `CustomSecureHeaders.php` for full usage.

