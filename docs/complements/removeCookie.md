## Examples

```php
$headers->applyOnOutput();

$headers->removeCookie('cookie1');

setcookie('cookie1');
setcookie('cookie2');
setcookie('cookIE3');

$headers->removeCookie('cookie3');
```

The cookie with the name `cookie2` will be sent, the others will be removed.

(Note there is no need to call [`->apply()`](apply) after any of this because [`->applyOnOutput()`](applyOnOutput) was configured to send the headers on the first byte of output).