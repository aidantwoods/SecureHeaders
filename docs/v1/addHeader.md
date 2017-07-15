## Description
```php
void addHeader (
    string $name
    [, string $value = null ]
)
```

`->addHeader()` is used to add a header to SecureHeaders' internal header list.

## Parameters
### name
The name of the header to add to SecureHeaders' internal header list.

### value
The value of the header

## Notes
The function [`->correctHeaderName`](correctHeaderName) may be used to determine whether to automatically strip a colon and any subsequent characters from the header name, and whether to auto-capitalise letters after dashes and at the beginning of the header name Like-Standard-Header-Names.