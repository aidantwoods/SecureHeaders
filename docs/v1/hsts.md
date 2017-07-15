## Description
```php
void hsts ( 
    [ int | string $maxAge = 31536000 
    [, mixed $subdomains = false 
    [, mixed $preload = false ] ] ] 
)
```

`->hsts()` is used to add and configure the Strict-Transport-Security header.

HSTS makes sure that a user's browser will fill the role of redirecting them from HTTP to HTTPS so that they need not trust an insecure response from the network.

## Parameters
### maxAge
The length, in seconds either as a string, or an integer – specify the length that a user's browser should remember that the application is HTTPS only.

### subdomains
Loosely casted as a boolean, whether to include the `includeSubDomains` flag – to deploy the HSTS policy across the entire domain.

### preload
Loosely casted as a boolean, whether to include the `preload` flag – to consent to have the domain loaded into [various preload lists](https://hstspreload.appspot.com/) (so that a user need not initially visit your site securely to know about the HSTS policy). 

You must also [manually preload](https://hstspreload.appspot.com/) your domain for this to take effect – the flag just indicates consent.
