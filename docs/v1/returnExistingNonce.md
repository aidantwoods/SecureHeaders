## Description
```php
void returnExistingNonce ( [ mixed $mode = true ] )
```

`->returnExistingNonce()` will determine the behaviour of [`->cspNonce`](cspNonce) and its aliases when a nonce for the specified directive already exists.

When enabled, the existing nonce will be returned. When disabled, a new nonce will be generated for the directive, added alongside the existing one, and the new nonce will be returned.

If not explicitly set, the default mode for this setting is enabled.

## Parameters
### mode
Loosely casted to a boolean, `true` enables the behaviour, `false` turns it off.