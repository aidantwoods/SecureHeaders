## Description
```php
void hpkpSubdomains (
    [ mixed $mode = true 
    [, mixed $reportOnly = null ] ] 
)
```

Add or remove the `includeSubDomains` flag from the [HPKP](hpkp) policy
(note this can be done with the [`->hpkp`](hpkp) function too).


## Parameters
### mode
Loosely casted to a boolean, `true` adds the `includeSubDomains` flag,
 `false` removes it.

### reportOnly
Apply this setting to the report-only version of the HPKP policy header
