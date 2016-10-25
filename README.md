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

## Basic Example 1
Here is a good implementation example
```php
$headers = new SecureHeaders();
$headers->hsts();
$headers->csp_allow('default', 'self');
$headers->csp_allow('script', 'https://my.cdn.org');
```

These few lines of code will take an application from a grade F, to a grade A on Scott Helme's https://securityheaders.io/

The following ways of declaring the following CSP above are equivalent:
```
Content-Security-Policy:default-src 'self'; script-src 'self' https://my.cdn.org;
```
#### Method 1
```php
$headers->csp_allow('default', 'self');
$headers->csp_allow('script', 'self');
$headers->csp_allow('script', 'https://my.cdn.org');
```
#### Method 2
```php
$headers->csp_allow('default-src', 'self');
$headers->csp_allow('script-src', 'self');
$headers->csp_allow('script-src', 'https://my.cdn.org');
```
#### Method 3
```php
$myCSP = array(
    'default-src' => [
        "'self'"
    ],
    'script-src' => [
        "'self'",
        'https://my.cdn.org'
    ]
);
$headers->csp($myCSP);
```

All of the above can be mixed in any order and will result in merged policies

## Basic Example 2
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
* The following header will also be removed (SecureHeaders will also attempt to remove the `Server` header, though it is unlikely this header will be under PHP jurisdiction)
  
  ```
  X-Powered-By
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


## Basic Example 3

If the following CSP is created

```php
$headers->csp_allow('default', '*');
$headers->csp_allow('script', 'unsafe-inline');
$headers->csp_allow('script', 'http://insecure.cdn.org');
$headers->csp_allow('style', 'https:');
$headers->csp_allow('style', '*');
$headers->add_csp_reporting('https://valid-enforced-url.org', 'whatisthis');
```

```
Content-Security-Policy:default-src *; script-src 'unsafe-inline' http://insecure.cdn.org; style-src https: *; report-uri https://valid-enforced-url.org;
Content-Security-Policy-Report-Only:default-src *; script-src 'unsafe-inline' http://insecure.cdn.org; style-src https: *; report-uri whatisthis;
```

The following messages will be issued with regard to CSP: (`level E_USER_WARNING` and `level E_USER_NOTICE`)

* The default-src directive contains a wildcard (so is a CSP bypass)

  ```
  Warning: Content Security Policy contains a wildcard * as a source value in default-src; this can allow anyone to insert elements covered by the default-src directive into the page.
  ```
* The script-src directive contains an a flag that allows inline script (so is a CSP bypass)

  ```
  Warning: Content Security Policy contains the 'unsafe-inline' keyword in script-src, which prevents CSP protecting against the injection of arbitrary code into the page.
  ```
* The script-src directive contains an insecure resource as a source value (HTTP responses can be trivially spoofed – spoofing allows a bypass)

  ```
  Warning: Content Security Policy contains the insecure protocol HTTP in a source value http://insecure.cdn.org; this can allow anyone to insert elements covered by the script-src directive into the page.
  ```
* The style-src directive contains two wildcards (so is a CSP bypass) – both wildcards are listed

  ```
  Warning: Content Security Policy contains the following wildcards https:, * as a source value in style-src; this can allow anyone to insert elements covered by the style-src directive into the page.
  ```
* The report only header was sent, but no/an invalid reporting address was given – preventing the report only header from doing anything useful in the wild

  ```
  Notice: Content Security Policy Report Only header was sent, but an invalid, or no reporting address was given. This header will not enforce violations, and with no reporting address specified, the browser can only report them locally in its console. Consider adding a reporting address to make full use of this header.
  ```

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


#### TODO
* HPKP reporting
* Basic CSP analysis, and warnings when policy apprears unsafe
