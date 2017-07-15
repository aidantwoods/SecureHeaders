## Description
```php
void doneOnOutput ( [ mixed $mode = true ] )
```

`->doneOnOutput()` is used to enable or disable output buffering with [`ob_start`](https://secure.php.net/manual/function.ob-start.php). When enabled, the `ob_start` callback will be set to automatically call [`->done()`](done) upon the first byte of output.

If unconfigured, the default setting for `->doneOnOutput` is off.

## Parameters
### mode
`mode` is the on/off setting. Any value of type that is loosely castable to a boolean is valid. Passing a boolean of value `true` will turn output buffering on, passing a boolean of value `false` will turn it off. The integers `1` and `0` will do the same respectively.


