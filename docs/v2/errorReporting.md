## Description
```php
void errorReporting ( mixed $mode )
```

Enable or disable error reporting.
Note that SecureHeaders will honour the PHP configuration for error
reporting level and for whether errors are displayed by default. If you
would like to specifically turn off errors from only SecureHeaders then
use this function.

## Parameters
### mode
Loosely casted as a boolean, `true` will enable error reporting
 (the default), `false` will disable it.
