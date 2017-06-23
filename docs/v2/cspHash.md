## Description
```php
string cspHash (
    string $friendlyDirective 
    , string $string 
    [, ?string $algo = 'sha256' 
    [, mixed $isFile = null 
    [, mixed $reportOnly = null ] ] ] 
)
```

Generate a hash of the provided [`$string`](#string) value, and have it
added to the [`$friendlyDirective`](#friendlyDirective) directive in CSP.


## Parameters
### friendlyDirective
The (case insensitive)
 [friendly name](friendly_directives_and_sources#directives) that the
 hash should be to be added to.

### string
The string that should be hashed and added to the
 [`$friendlyDirective`](friendly_directives_and_sources#directives)
 directive.

### algo
 The hashing algorithm to use. CSP currently supports `sha256`,
 `sha384`, `sha512`.

### isFile
Loosely casted as a boolean. Indicates that [`$string`](string) instead
 specifies a file path.

### reportOnly
Loosely casted as a boolean. Indicates that the hash should be added
 to the report only policy `true`, or the enforced policy `false`.

## Return Values
Returns the hash value.