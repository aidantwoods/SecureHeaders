# SecureHeaders

A PHP class aiming to make the use of browser security features more accessible, while allowing developers to safely experiment with these features to ensure they are configured correctly.

## Notice
This project is currently under initial development, so expect changes to the source code at any time which may break forwards compatability or change/remove functionality. That said, bug and issue reports are still welcome from anyone who wants to test it out.

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

The `SecureHeaders` class can also be extended to include the `$baseCSP` on all pages.
e.g.

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

