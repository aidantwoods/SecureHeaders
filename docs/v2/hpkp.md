## Description
```php
void hpkp (
    string | array $pins 
    [, ?integer | string $maxAge = null 
    [, ?mixed $subdomains = null 
    [, ?string $reportUri = null 
    [, mixed $reportOnly = null ] ] ] ] 
)
```

Add and configure the HTTP Public Key Pins header.


## Parameters
### pins
Either give a valid pin as a string here, or give multiple as an array.
 **Note that browsers will not enforce this header unless a backup pin
 AND a pin that is currently deployed is specified)**. This means that
 at least two pins must be specified. (to do this by passing strings,
 simply call [`->hpkp`](hpkp) again with the second pin as the first
 argument).

 Valid array syntax is as follows
 ```php
 $pins = array(
     array('sha256', 'pin1'),
     array('pin2'),
     array('pin3', 'sha256')
 );
 $headers->hpkp($pins);
 ```

 The above will add `pin1`, `pin2`, and `pin3` with the associated hash
 label `sha256`. This is the only valid *  HPKP hashing algorithm at
 time of writing.

### maxAge
The length, in seconds that a browser should enforce the policy after
 last receiving it.

 If this is left unset across all calls to  [`->hpkp`](hpkp), the value will
 default to 10 seconds (which isn't much use – so it is best to set the
 value).

 Passing `null` indicates that a maxAge should not be modified on this
 call (e.g. can be used to prevent overwriting a previous setting).

### subdomains
Loosely casted to a boolean, whether to include the `includeSubDomains`
 flag to deploy the policy across the entire domain. `true` enables this
 flag.

 Passing `null` indicates that a subdomains should not be modified on
 this call (e.g. can be used to prevent overwriting a previous setting).

### reportUri
A reporting address to send violation reports to.

 Passing `null` indicates that a reporting address should not be modified
 on this call (e.g. can be used to prevent overwriting a previous
 setting).

### reportOnly
Loosely cased to a boolean. If `true`, settings will apply to the
 report-only version of this header.
