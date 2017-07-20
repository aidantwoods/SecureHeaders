## Description
```php
void protectedCookie (
    string | array $name 
    [, integer $mode = self::COOKIE_DEFAULT ] 
)
```

Configure which cookies SecureHeaders will regard as protected.
SecureHeaders will consider substrings and names of cookies separately.
By default, cookies that case insensitively match the following
substrings or names will be regarded as protected.

#### Substrings
```
sess
auth
login
csrf
xsrf
token
antiforgery
```

#### Names
```
sid
s
persistent
```

If a cookie is protected, then cookie flags will be appended as
configured by [`->auto`](auto). The default behaviour is to add `Secure`,
`HttpOnly`, and `SameSite=Lax` to ensure cookies are both sent securely,
out of the reach of JavaScript, and fairly resistant to csrf attacks.

## Parameters
### name
The name (or substring of the name, depending on mode configuration),
 of the cookie to add/remove from the protection list (depending on mode
 configuration). Or a list of cookie names (or substrings of the name to
 match) as an array of strings.

### mode
`mode` accepts one or more of the following constants. Multiple
  constants may be specified by combination using
 [bitwise operators](https://secure.php.net/manual/language.operators.bitwise.php)

## Valid Constants

### COOKIE_DEFAULT
```php
SecureHeaders::COOKIE_DEFAULT = ~SecureHeaders::COOKIE_REMOVE
                              &  SecureHeaders::COOKIE_SUBSTR
```
`COOKIE_DEFAULT` enables not `COOKIE_REMOVE` (i.e. add the cookie to the list), and causes [`$name`](#name) to refer to a cookie name substring (or substrings if an array is given).

### COOKIE_NAME
```php
SecureHeaders::COOKIE_NAME
```
`COOKIE_NAME` will add the string, or strings specified in [`$name`](#name) to the list of (case insensitive) protected cookie names.

### COOKIE_SUBSTR
```php
SecureHeaders::COOKIE_SUBSTR
```
`COOKIE_SUBSTR` will add the string, or strings specified in [`$name`](#name) to the list of (case insensitive) protected cookie substrings (of the cookie name).

### COOKIE_ALL
```php
SecureHeaders::COOKIE_ALL = SecureHeaders::COOKIE_NAME
                          | SecureHeaders::COOKIE_SUBSTR
```
`COOKIE_ALL` will enable behaviours controlled by both [`COOKIE_NAME`](#COOKIE_NAME), AND [`COOKIE_SUBSTR`](#COOKIE_SUBSTR)

### COOKIE_REMOVE
```php
SecureHeaders::COOKIE_REMOVE
```
`COOKIE_REMOVE` when combined with either `COOKIE_NAME`, `COOKIE_SUBSTR` or `COOKIE_ALL` will cause the string or strings specified in [`$name`](#name) to be removed from the respective lists, if such entries exist.
