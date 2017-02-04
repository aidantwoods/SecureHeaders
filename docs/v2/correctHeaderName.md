## Description
```php
void correctHeaderName ( [ mixed $mode = true ] )
```

`->correctHeaderName()`, in the context of the [`header`](header)/[`addHeader`](addHeader) function to determine whether to automatically strip a colon and any subsequent characters from the header name, and whether to auto-capitalise letters after dashes and at the beginning of the header name Like-Standard-Header-Names.

If this setting is not set explicitly the internal default is `true`.

## Parameters
### mode
Mode is loosely casted to a boolean, `true` enables the correction and capitalisation behaviour, `false` disables it.