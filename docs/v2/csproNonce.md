## Description
```php
string csproNonce(
    string $friendlyDirective
)
```

`->csproNonce()` is an alias for [`->cspNonce()`](cspNonce) with [reportOnly](cspNonce#reportOnly) set to true.

**Make sure not to use nonces where the content given the nonce is partially of user origin! This would allow an attacker to bypass the protections of CSP!**