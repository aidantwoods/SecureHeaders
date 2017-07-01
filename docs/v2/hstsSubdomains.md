## Description
```php
void hstsSubdomains ([ mixed $mode = true ] )
```

Add or remove the `includeSubDomains` flag from the [HSTS](hsts) policy
(note this can be done with the [`->hsts`](hsts) function too).


## Parameters
### mode
Loosely casted to a boolean, `true` adds the `includeSubDomains` flag,
 `false` removes it.
