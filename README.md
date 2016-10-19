# SecureHeaders

A PHP class aiming to make the use of browser security features more accessible, while allowing developers to safely experiment with these features to ensure they are configured correctly.

## Development Notice
This project is currently under initial development, so there is the potential for non-backwards compatible changes etc.. That said, bug reports are still welcome from anyone who wants to test it out.

## Features
* Add/remove and manage headers easily
* Build a Content Security Policy, or combine multiple together
* Correct cookie flags on already set cookies to add httpOnly and secure flags, (if the cookies appear to be session related)
* Safe mode prevents accidential self-DOS when using HSTS, or HPKP
* Receive warnings about missing security headers (`level E_USER_WARNING`)

## Usage
e.g. the following will combine `$baseCSP` with `$csp` to create an overall Content-Security-Policy.
```php
import('SecureHeaders.php');

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
```

The `SecureHeaders` class can also be extended to so that custom settings can be applied on all instances of the extension.
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
import('SecureHeaders.php');
import('CustomSecureHeaders.php');

$headers = new CustomSecureHeaders();

$pageSpecificCSP = array(
  "frame-src" => ["https://www.example.com/"],
  "style-src" => ["'nonce-$style_nonce'"],
  "script-src" => ["'nonce-$script_nonce'"]
);
$headers->csp($pageSpecificCSP);
```

etc...

This readme is incomplete, please refer to the source, or the (non-exhaustive) example file `CustomSecureHeaders.php` for full usage.

