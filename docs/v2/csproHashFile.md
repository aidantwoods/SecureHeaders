## Description
```php
string csproHashFile (
    string $friendlyDirective 
    , string $string 
    [, ?string $algo = 'sha256' ] 
)
```

An alias for [`->cspHash`](cspHash) with [reportOnly](cspHash#reportOnly) set
to true, and [isFile](cspHash#isFile) set to true.

