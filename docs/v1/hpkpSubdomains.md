## Description
```php
void hpkpSubdomains ( [ mixed $mode = true ] )
```

`->hpkpSubdomains()` is used add or remove the `includeSubDomains` flag from the [HPKP](hpkp) policy (note this can be done with the hpkp function too).

## Parameters
### mode
Loosely casted to a boolean, `true` adds the `includeSubDomains` flag, `false` removes it.