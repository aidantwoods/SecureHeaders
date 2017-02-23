SecureHeaders deliberately doesn't have its own `__construct` function that needs implementing, so that extending can be as easy as possible. Simply fill your own `__construct` function with as many defaults as you'd like to apply, and create an instance of your extension instead!

Take a browse through the functions on the right to see what kind of functionality is available to you. Of course, any defaults you don't change will be carried through to the extension – so you can still benefit from [`->auto`](auto) and all its contained functions.

Here are some examples of what you might want to include:

### Baseline CSP
Need a base CSP on every page, this one automatically adds Google's font CDN, the current origin, and font awesome from Cloudflare's CDN as a base CSP.
```php
class CustomSecureHeaders extends SecureHeaders{
    public function __construct()
    {
        $this->csp($this->base);
    }

    private $base = array(
        'default' => 'self',
        'style' => [
            'self',
            'https://fonts.googleapis.com/',
            'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/'
        ]
    );
}
```
A page that wants to use this, now only need the following:
```php
$headers = new CustomSecureHeaders;
```

Of course, if you want to add additional CSP sources on the fly per page, simply call [`->csp`](csp) at some point before [`->done`](done).


### Auto send headers
Don't want to have to call [`->done`](done), write an extension that enables [`->doneOnOutput`](doneOnOutput) on instance construction.
```php

class CustomSecureHeaders extends SecureHeaders{
    public function __construct()
    {
        $this->doneOnOutput();
    }
}
```
Similar to above, you now only need to create an instance of your extension to apply that default.
```php
$headers = new CustomSecureHeaders;
```

### Whatever suits you
This one will enable [`->doneOnOutput`](doneOnOutput), generate some nonces to use for `style-src` and `script-src`, and enable [`->strictMode`](strictMode).

```php
class CustomSecureHeaders extends SecureHeaders{    
    public function __construct()
    {
        $this->doneOnOutput();

        $this->strictMode();

        $this->cspNonce('style');
        $this->cspNonce('script');
    }
}
```

Again, this can all be applied by creating an instance of the extension
```php
$headers = new CustomSecureHeaders;
```

Note that by default [`cspNonce`](cspNonce) will return an existing nonce value. This should make embedding the nonce value in any scripts or style attributes relatively easy.
E.g. the nonce for `script-src` can be accessed globally via `$headers->cspNonce('script')` (without generating a new unnecessary one). The nonce for `style-src` could also be accessed in a similar fashion.

**Make sure not to use nonces where the content given the nonce is partially of user origin! This would allow an attacker to bypass the protections of CSP!**