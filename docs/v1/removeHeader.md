## Description
```php
boolean removeHeader ( string $name )
```

`->removeHeader()` is used to queue a header for removal.

Upon calling [`->done`](done) the header will be removed. This function can be used to manually prevent [automatic headers](auto) from being sent.

## Parameters
### name
Case insensitive name of the header to remove.

## Return Values
`->removeHeader()` will return either true or false indicating whether the header specified *was* present in the internal header list (note that automatic headers will not appear in this list).

Calling this function guarantees removal of the specified header, the return value only aims to provide some context as to whether the function had an effect.