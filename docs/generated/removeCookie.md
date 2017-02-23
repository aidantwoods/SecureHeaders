## Description
```php
void removeCookie ( string $name )
```

Remove a cookie from SecureHeaders' internal list (thus preventing the
`Set-Cookie` header for that specific cookie from being sent).
This allows you to form a blacklist for cookies that should not be sent
(either programatically or globally, depending on where this is
configured).

## Parameters
### name
The (case-insensitive) name of the cookie to remove.

## Examples

```php
$headers->doneOnOutput();

$headers->removeCookie('cookie1');

setcookie('cookie1');
setcookie('cookie2');
setcookie('cookIE3');

$headers->removeCookie('cookie3');
```

The cookie with the name `cookie2` will be sent, the others will be removed.

(Note there is no need to call [`->done()`](done) after any of this because [`->doneOnOutput()`](doneOnOutput) was configured to send the headers on the first byte of output).