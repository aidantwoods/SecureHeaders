## Description
```php
void sameSiteCookies ( [ string $mode = null ] )
```

`->sameSiteCookies()` is used to add and configure the default setting for [protected cookies](protectedCookie) that are automatically marked as `SameSite`.

If this setting is unspecified the default will be `SameSite=Lax`, if this setting is given an invalid `string` setting the last setting will be honoured. If [`->strictMode`](strictMode) is enabled then the default will be `SameSite=Strict` under the same criteria for set value. If you wish to disable making cookies as same site, see [`->auto`](auto#AUTO_COOKIE_SAMESITE).

## Parameters
### mode
Valid values for `$mode` are either (case-insensitively) the strings `'Lax'` and `'Strict'`. If `null` is passed the setting will revert to the default as defined above. If another `string` is passed then the call will be ignored and the previous setting will be retained (if no setting was specified previously then the default will remain).