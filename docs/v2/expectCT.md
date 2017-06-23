## Description
```php
void expectCT (
    [ ?int | string $maxAge = 31536000 
    [, ?mixed $enforce = true 
    [, ?string $reportUri = null ] ] ] 
)
```

Used to add and configure the Expect-CT header.
Expect-CT makes sure that a user's browser will fill the role of
ensuring that future requests, within $maxAge seconds will have
certificate transparancy.

If set to enforcement mode, the browser will fail the TLS connection if
the certificate transparency requirement is not met

## Parameters
### maxAge
The length, in seconds either as a string, or an integer – specify the
 length that a user's browser should remember that the application
 should be delivered with a certificate transparency expectation.

### enforce
Loosely casted as a boolean, whether to enforce (by failing the TLS
 connection) that certificate transparency is enabled for the next
 $maxAge seconds, or whether to only report to the console, and to
 $reportUri if an address is defined.

### reportUri
A reporting address to send violation reports to.

 Passing `null` indicates that a reporting address should not be modified
 on this call (e.g. can be used to prevent overwriting a previous
 setting).
