## Description
```php
void strictMode ( [ mixed $mode = true ] )
```

`->strictMode()` will turn strict mode on or off.

* When enabled, strict mode will auto-enable HSTS with a 1 year duration, and the `includeSubDomains` and `preload` flags set. Note that this HSTS policy is made as a [header proposal](header-proposals), and can thus be removed or modified.

* The source keyword `'strict-dynamic'` will also be added to the first of the following directives that exist: `script-src`, `default-src`; only if that directive also contains a nonce or hash source value, and not otherwise.

  This will disable the source whitelist in `script-src` in CSP3 compliant browsers. The use of whitelists in script-src is [considered not to be an ideal practice][1], because they are often trivial to bypass.

  [1]: https://research.google.com/pubs/pub45542.html "The Insecurity of Whitelists and the Future of Content Security Policy"

  Don't forget to [manually submit](https://hstspreload.appspot.com/) your domain to the HSTS preload list if you are using this option.

* The default `SameSite` value injected into [protected cookies](protectedCookie) will be changed from `SameSite=Lax` to `SameSite=Strict`. See [`->auto`](auto#AUTO_COOKIE_SAMESITE) to enable/disable injection of `SameSite` and [`->sameSiteCookies`](sameSiteCookies) for more on specific behaviour and to explicitly define this value manually, to override the default.


## Parameters
### mode
Loosely casted to a boolean, `true` enables strict mode, `false` turns it off.
