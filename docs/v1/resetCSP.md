## Description
```php
void resetCSP( mixed $reportOnly = null )
```

`->resetCSP()` is used to reset the CSP.

## Parameters
### reportOnly
Loosely casted to a boolean, `true` resets the policy configured by [`->cspro`](cspro), `false` resets the policy configured by [`->csp`](csp).