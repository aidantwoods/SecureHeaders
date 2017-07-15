## Description
```php
boolean removeCSPSource(
    string $directive,
    string $source
    [, mixed $reportOnly = null ]
)
```

`->removeCSPSource()` is used to remove a previously added source from a CSP directive.

## Parameters
### directive
The directive (case insensitive) in which the source to be removed resides.

### source
The source (case insensitive) to remove

### reportOnly
Loosely casted as a boolean, `true` ensures the function acts on the report only policy, `false` (the default, as `null` casts to false) ensures the function acts on the enforced policy.