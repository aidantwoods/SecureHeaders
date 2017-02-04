## Description
```php
string cspHashFile(
    string $friendlyDirective,
    string $string
    [, string $algo = 'sha256'
    [, mixed $reportOnly = null ] ]
)
```

`->cspHashFile()` is an alias for [`->cspHash`](cspHash) with [isFile](cspHash#isFile) set to true.