## Description
```php
void hstsSubdomains ( [ mixed $mode = true ] )
```

`->hstsSubdomains()` is used add or remove the `includeSubDomains` flag from the [HSTS](hsts) policy (note this can be done with the hsts function too).

## Parameters
### mode
Loosely casted to a boolean, `true` adds the `includeSubDomains` flag, `false` removes it.