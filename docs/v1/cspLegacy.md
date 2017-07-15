## Description
```php
void cspLegacy ( mixed $mode = true )
```

`->cspLegacy()` is used to enable or disable legacy CSP support.

When enabled, SecureHeaders will send an additional `X-Content-Security-Policy` and/or `X-Content-Security-Policy-Report-Only`. The policy configured with [`->csp`](csp) or [`->cspro`](cspro) respectively will be sent with this legacy header, with no attempt to strip out newer CSP features (browsers should ignore CSP directives and keywords they do not recognise).

If this setting is unconfigured, the default is off.

## Parameters
### mode
Loosely casted as a boolean, `true` enables the legacy headers, `false` disables them.