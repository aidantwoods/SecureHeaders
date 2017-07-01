## Description
```php
void applyOnOutput (
    [ HttpAdapter $http = null 
    [, mixed $mode = true ] ] 
)
```

Used to enable or disable output buffering with ob_start.
When enabled, the ob_start callback will be set to automatically call
[`->apply`](apply) upon the first byte of output.

If unconfigured, the default setting for [`->applyOnOutput`](applyOnOutput) is off.

## Parameters
### http


### mode
mode is the on/off setting. Any value of type that is loosely castable to a boolean is valid.

 Passing a boolean of value true will turn output buffering on,
 passing a boolean of value false will turn it off. The integers
 1 and 0 will do the same respectively.
