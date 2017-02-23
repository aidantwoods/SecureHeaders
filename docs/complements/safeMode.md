## Examples
For example, if the following code was run (safe mode can be called at any point before `->done()` to be effective)
```php
$headers->hsts();
$headers->safeMode();
```
HSTS would still be enabled (as asked), but would be limited to lasting 24 hours.
SecureHeaders would also generate the following notice

> **Notice:** HSTS settings were overridden because Safe-Mode is enabled. [Read about](https://scotthelme.co.uk/death-by-copy-paste/#hstsandpreloading) some common mistakes when setting HSTS via copy/paste, and ensure you [understand the details](https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet) and possible side effects of this security feature before using it.

*What if I set it via a method not related to SecureHeaders? Can SecureHeaders still enforce safe mode?*

Yup! SecureHeaders will look at the names and values of headers independently of its own built in functions that can be used to generate them.

For example, if I use PHPs built in header function to set HSTS for 1 year, for all subdomains, and indicate consent to preload that rule into major browsers, and then (before or after setting that header) enable safe-mode...

```php
header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
$headers->safeMode();
```

The same above notice will be generated, max-age will be modified to 1 day, and the preload and includesubdomains flags will be removed. 