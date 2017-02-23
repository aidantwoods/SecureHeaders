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
