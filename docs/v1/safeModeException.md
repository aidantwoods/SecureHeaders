## Description
```php
void safeModeException ( string $name )
```

`->safeModeException()` is used to add an exception to safe mode.

## Parameters
### name
Specify the name of the header that you wish to be exempt from safe mode warnings and auto-modification.

(Note that if you want to turn safe mode off for all headers, use [`->safeMode(false)`](safeMode) – safe mode is **not** on by default.)

## Examples
If you would like to enable safe mode and allow full use of the HSTS header, but still protect against accidental misuse of the HPKP header, the following would work.
```php
$headers->hsts();
$headers->safeMode();
$headers->safeModeException('strict-transport-security');
```

