## Description
```php
string cspNonce(
    string $friendlyDirective
    [, mixed $reportOnly = null ]
)
```

`->cspNonce()` can be used to securely generate a nonce value, and have it be added to the [`$friendlyDirective`](#friendlyDirective) in CSP.

Note that if a nonce already exists for the specified directive, the existing value will be returned instead of generating a new one (multiple nonces in the same directive don't offer any security benefits at present – since they're all treated equally). This should facilitate distributing the nonce to any code that needs it (provided the code can access the SecureHeaders instance).

If you want to disable returning an existing nonce, use [`->return_existing_nonce`](return_existing_nonce) to turn the behaviour on or off.

**Make sure not to use nonces where the content given the nonce is partially of user origin! This would allow an attacker to bypass the protections of CSP!**

## Parameters
### friendlyDirective
The (case insensitive) [friendly name](friendly_directives_and_sources#directives) that the nonce should be to be added to.

### reportOnly
Loosely casted as a boolean. Indicates that the hash should be added to the report only policy `true`, or the enforced policy `false`.

## Return Values
Returns the nonce value