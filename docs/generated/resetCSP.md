## Description
```php
void resetCSP ([ mixed $reportOnly = null ] )
```

Reset the CSP.


## Parameters
### reportOnly
Loosely casted to a boolean, `true` resets the policy configured by
[`->cspro`](cspro), `false` resets the policy configured by [`->csp`](csp).
