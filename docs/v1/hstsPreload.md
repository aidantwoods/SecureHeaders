## Description
```php
void hstsPreload ( [ mixed $mode = true ] )
```

`->hstsPreload()` is used add or remove the `preload` flag from the [HSTS](hsts) policy (note this can be done with the hsts function too).

## Parameters
### mode
Loosely casted to a boolean, `true` adds the `preload` flag, `false` removes it.