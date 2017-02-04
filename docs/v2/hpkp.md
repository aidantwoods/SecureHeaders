## Description
```php
void hpkp ( 
    string | array $pins
    [, int | string $maxAge = null
    [, mixed $subdomains = null 
    [, string $reportUri = null ] ] ] 
)
```

`->hpkp()` is used to add and configure the HTTP Public Key Pins header.

## Parameters
### pins
Either give a valid pin as a string here, or give multiple as an array. **Note that browsers will not enforce this header unless a backup pin AND a pin that is currently deployed is specified)**. This means that at least two pins must be specified. (to do this by passing strings, simply call `->hpkp` again with the second pin as the first argument).

Valid array syntax is as follows
```php
$pins = array(
    array('sha256', 'pin1'),
    array('pin2'),
    array('pin3', 'sha256')
);
$headers->hpkp($pins);
```

The above will add `pin1`, `pin2`, and `pin3` with the associated hash label `sha256`. This is the only valid HPKP hashing algorithm at time of writing. The default will be updated as newer algorithms become available **make sure you either read the changelog or specify the algorithm you want to use to avoid breakage across updates**.

### maxAge
The length, in seconds that a browser should enforce the policy after last receiving it.

If this is left unset across all calls to  `->hpkp`, the value will default to 10 seconds (which isn't much use – so it is best to set the value).

### subdomains
Loosely casted to a boolean, whether to include the `includeSubDomains` flag to deploy the policy across the entire domain. `true` enables this flag.

### reportUri
A reporting address to send violation reports to.