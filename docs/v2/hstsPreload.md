## Description
```php
void hstsPreload ([ mixed $mode = true ] )
```

Add or remove the `preload` flag from the [HSTS](hsts) policy (note this
can be done with the [`->hsts`](hsts) function too).


## Parameters
### mode
Loosely casted to a boolean, `true` adds the `preload` flag, `false`
 removes it.
