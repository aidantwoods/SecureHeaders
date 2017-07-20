## Description
```php
HeaderBag apply ([ ?HttpAdapter $http = new GlobalHttpAdapter ] )
```

Calling this function will initiate the following
1. Existing headers from the HttpAdapter's source will be imported into
   SecureHeaders' internal list, parsed
2. [Automatic header functions](auto) will be applied
3. [Expect CT](expectCT), [CSP](csp), [HSTS](hsts), and [HPKP](hpkp)
   policies will be compiled and added to SecureHeaders' internal header
   list.
4. Headers queued for [removal](removeHeader) will be deleted from
   SecureHeaders' internal header list
5. [Safe Mode](safeMode) will examine the list of headers, and make any
   required changes according to its settings
6. The HttpAdapter will be instructed to remove all headers from its
   header source, Headers will then be copied from SecureHeaders'
   internal header list, into the HttpAdapter's (now empty) list of
   headers
7. If [error reporting](errorReporting) is enabled (both within
   SecureHeaders and according to the PHP configuration values for
   error reporting, and whether to display errors)
   * Missing security headers will be reported as `E_USER_WARNING`
   * Misconfigured headers will be reported as `E_USER_WARNING` or
     `E_USER_NOTICE` depending on severity, the former being most
     severe an issue.

 **Note:** Calling this function is **required** before the first byte
 of output in order for SecureHeaders to (be able to) do anything. If
 you're not sure when the first byte of output might occur, or simply
 don't want to have to call this every time – take a look at
 [`->applyOnOutput`](applyOnOutput) to have SecureHeaders take care of this for you.

## Parameters
### http
 An implementation of the [`->HttpAdapter`](HttpAdapter) interface, to which
 settings configured via SecureHeaders will be applied.

## Return Values
Returns the headers