## Description
```php
void removeHeader ( string $name )
```

Queue a header for removal.
Upon calling [`->apply`](apply) the header will be removed. This function can
be used to manually prevent [automatic headers](auto) from being sent.

## Parameters
### name
Case insensitive name of the header to remove.
