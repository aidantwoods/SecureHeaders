## Description
```php
void hpkpro (
    string | array $pins 
    [, ?integer | string $maxAge = null 
    [, ?mixed $subdomains = null 
    [, ?string $reportUri = null ] ] ] 
)
```

Add and configure the HTTP Public Key Pins header in report-only mode.
This is an alias for [`->hpkp`](hpkp) with `$reportOnly` set to `true`.
