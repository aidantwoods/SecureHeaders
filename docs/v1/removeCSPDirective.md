## Description
```php
boolean removeCSPDirective(
    string $directive
    [, mixed $reportOnly = null ]
)
```

`->removeCSPDirective()` is used to remove a previously added directive from CSP.

## Parameters
### directive
The directive (case insensitive) to remove.

### reportOnly
Loosely casted as a boolean, `true` ensures the function acts on the report only policy, `false` (the default, as `null` casts to false) ensures the function acts on the enforced policy.