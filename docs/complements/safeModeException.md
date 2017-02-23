## Examples
If you would like to enable safe mode and allow full use of the HSTS header, but still protect against accidental misuse of the HPKP header, the following would work.
```php
$headers->hsts();
$headers->safeMode();
$headers->safeModeException('strict-transport-security');
```
