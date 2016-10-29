# SecureHeaders
A PHP class aiming to make the use of browser security features more accessible, while allowing developers to safely experiment with these features to ensure they are configured correctly.

The project aims help increase the overall security of an application in-which it runs within, by taking advantage of security features that can be enabled via HTTP headers. 

Sometimes this is most appropriately applied through feedback. SecureHeaders will issue warnings (`level E_USER_WARNING`) and notices (`level E_USER_NOTICE`) at runtime when it notices something is wrong.
As per standard practice, it is advised that errors are turned off in any live system. SecureHeaders will respect the standard PHP `error_reporting` settings, and will also respect the `display_errors` configuration. 

In some cases, correcting insecure behaviour is best done pro-actively. SecureHeaders will modify or add headers (where safe to do so). (This can of course be granularly controlled, or outright disabled). This includes adding security flags to cookies with certain keywords in their names in an effort to protect session data. And also by adding missing security headers to automatically enable client browser security features.

## Development Notice
This project is currently under initial development, so there is the potential for non-backwards compatible changes etc.. That said, bug reports are still welcome from anyone who wants to test it out.

## Features
* Add/remove and manage headers easily
* Build a Content Security Policy, or combine multiple together
* Correct cookie flags on already set cookies to add httpOnly and secure flags, (if the cookies appear to be session related)
* Safe mode prevents accidential self-DOS when using HSTS, or HPKP
* Receive warnings about missing security headers (`level E_USER_WARNING`)

## Basic Example
Here is a good implementation example
```php
$headers = new SecureHeaders();
$headers->hsts();
$headers->csp('default', 'self');
$headers->csp('script', 'https://my.cdn.org');
```

These few lines of code will take an application from a grade F, to a grade A on Scott Helme's https://securityheaders.io/

Note that in the above, SecureHeaders has accepted a CSP directive shorthand, namely `default` and `script`, each corresponding to the `default-src` and `script-src` directives respectively. SecureHeaders will look for any shorthands it recognised, but will keep values it doesn't in tact – so that both the full directive name, or the shorthand can be used. For a more in-depth explanation on the `csp` function used here, see [Using CSP](#using-csp) 


## Basic Example 2
An 'out-of-the-box' example is as follows:
```php
$headers = new SecureHeaders();
$headers->done();
```

With such code, the following will occur:
* Warnings will be issued (`E_USER_WARNING`)

  ```
  Warning: Missing security header: 'Strict-Transport-Security'
  Warning: Missing security header: 'Content-Security-Policy'
  ```
* The following headers will be automatically added

  ```
  X-Content-Type-Options:nosniff
  X-Frame-Options:Deny
  X-XSS-Protection:1; mode=block
  ``` 
* The following header will also be removed (SecureHeaders will also attempt to remove the `Server` header, though it is unlikely this header will be under PHP jurisdiction)
  
  ```
  X-Powered-By
  ```

Additionally, if any cookies have been set (at any time before `->done()` is called) e.g.
```php
setcookie('auth', 'supersecretauthenticationstring');

$headers = new SecureHeaders();
$headers->done();
```
Even though in the current PHP configuration, cookie flags `Secure` and `HTTPOnly` do **not** default to on, the end result of the `Set-Cookie` header will be
```
Set-Cookie:auth=supersecretauthenticationstring; secure; HttpOnly
```

This is because the cookie name contains a keyword substring (`auth` in this case). When SecureHeaders sees this it will pro-actively inject the `Secure` and `HTTPOnly` flags into the cookie, in an effort to correct an error that could lead to session hijacking.


## Basic Example 3

If the following CSP is created

```php
$headers->csp('default', '*');
$headers->csp('script', 'unsafe-inline');
$headers->csp('script', 'http://insecure.cdn.org');
$headers->csp('style', 'https:');
$headers->csp('style', '*');
$headers->add_csp_reporting('https://valid-enforced-url.org', 'whatisthis');
```

```
Content-Security-Policy:default-src *; script-src 'unsafe-inline' http://insecure.cdn.org; style-src https: *; report-uri https://valid-enforced-url.org;
Content-Security-Policy-Report-Only:default-src *; script-src 'unsafe-inline' http://insecure.cdn.org; style-src https: *; report-uri whatisthis;
```

The following messages will be issued with regard to CSP: (`level E_USER_WARNING` and `level E_USER_NOTICE`)

* The default-src directive contains a wildcard (so is a CSP bypass)

  ```
  Warning: Content Security Policy contains a wildcard * as a source value in default-src; this can allow anyone to insert elements covered by the default-src directive into the page.
  ```
* The script-src directive contains an a flag that allows inline script (so is a CSP bypass)

  ```
  Warning: Content Security Policy contains the 'unsafe-inline' keyword in script-src, which prevents CSP protecting against the injection of arbitrary code into the page.
  ```
* The script-src directive contains an insecure resource as a source value (HTTP responses can be trivially spoofed – spoofing allows a bypass)

  ```
  Warning: Content Security Policy contains the insecure protocol HTTP in a source value http://insecure.cdn.org; this can allow anyone to insert elements covered by the script-src directive into the page.
  ```
* The style-src directive contains two wildcards (so is a CSP bypass) – both wildcards are listed

  ```
  Warning: Content Security Policy contains the following wildcards https:, * as a source value in style-src; this can allow anyone to insert elements covered by the style-src directive into the page.
  ```
* The report only header was sent, but no/an invalid reporting address was given – preventing the report only header from doing anything useful in the wild

  ```
  Notice: Content Security Policy Report Only header was sent, but an invalid, or no reporting address was given. This header will not enforce violations, and with no reporting address specified, the browser can only report them locally in its console. Consider adding a reporting address to make full use of this header.
  ```

## Using CSP
Let's take a look at a few ways of declaring the following CSP (newlines and indentation added here for readability)
```
Content-Security-Policy:
    default-src 'self'; 
    script-src 'self' https://my.cdn.org https://scripts.cdn.net https://other.cdn.com; 
    img-src https://images.cdn.xyz; 
    style-src https://amazingstylesheets.cdn.pizza; 
    base-uri 'self'; 
    form-action 'none'; 
    upgrade-insecure-requests; 
    block-all-mixed-content;
```
#### CSP as an array
```php
$myCSP = array(
    'default-src' => [
        "'self'"
    ],
    'script-src' => [
        'self',
        'https://my.cdn.org',
        'https://scripts.cdn.net',
        'https://other.cdn.com'
    ],
    'img-src' => ['https://images.cdn.xyz'],
    'style-src' => 'https://amazingstylesheets.cdn.pizza',
    'base' => 'self',
    'form' => 'none',
    'upgrade-insecure-requests' => [],
    'block-all-mixed-content'
);

$headers->csp($myCSP);
```

In the above, we've specified the policy using an array in the way it makes the most sense (bar some slight variation to demonstrate supported syntax).
We then passed our policy array to the `csp` function.

Within the array, take a look at `default-src`. This is the full directive name (the key of the array), and its source list is specified as an array containing source values. In this case, the directive only has one source value, `'self'`, which is spelled out in full (note the single quotes within the string).

In this case, we've actually written a lot more than necessary – see the directive `base` for comparison. The actual CSP directive here is `base-uri`, but `base` is a supported shorthand by SecureHeaders. Secondly, we've ommited the array syntax from the decending source list entirely – we only wanted to declare one valid source, so SecureHeaders supports foregoing the array structure if its not useful. Additionally, we've made use of a shorthand within the source value too – omitting the single quotes from the string's value (i.e. `self` is a shorthand for `'self'`).

There are two CSP 'flags' included also in this policy, namely `upgrade-insecure-requests` and `block-all-mixed-content`. These do not hold any source values (and would not be valid in CSP if they did). You can specify these by either giving an empty array, an array containing only `null`, or forgoing any mention of decendents entirely (as shown in `block-all-mixed-content`, which is written as-is).

The `csp` function also supports combining these CSP arrays, so the following would combine the csp defined in `$myCSP`, and `$myOtherCSP`. You can combine as many csp arrays as you like by adding additional arguments.

```php
$headers->csp($myCSP, $myOtherCSP);
```

#### CSP as ordered pairs
Using the same `csp` function as above, you can add sources to directives as follows
```php
$headers->csp('default', 'self');
$headers->csp('script', 'self');
$headers->csp('script', 'https://my.cdn.org');
```
or if you prefer to do this all in one line
```php
$headers->csp('default', 'self', 'script', 'self', 'script', 'https://my.cdn.org');
```

Note that directives and sources are specified as ordered pairs here.

If you wanted to add a CSP flag in this way, simply use one of the following.
```php
$headers->csp('upgrade-insecure-requests');
$headers->csp('block-all-mixed-content', null);
```
Note that the second way is necessary if embedded in a list of ordered pairs – otherwise SecureHeaders can't tell what is a directive name or a source value.
e.g. this would set `block-all-mixed-content` as a CSP flag, and `https://my.cdn.org` as a script-src source value.
```php
$headers->csp('block-all-mixed-content', null, 'script', 'https://my.cdn.org');
```

**However**, the `csp` function also supports mixing these ordered pairs with the array structure, and a string without a source at the end of the argument list will also be treated as a flag. You could, *in perhaps an abuse of notation*, use the following to set two CSP flags and the policy contained in the `$csp` array strucure.

```php
$headers->csp('block-all-mixed-content', $csp, 'upgrade-insecure-requests');
```

#### CSP as, uhh..
The CSP function aims to be as tolerant as possible, a CSP should be able to be communicated in whatever way is easiest to you.

That said, please use responsibly – the following is quite hard to read

```php
$myCSP = array(
    'default-src' => [
        "'self'"
    ],
    'script-src' => [
        "'self'",
        'https://my.cdn.org'
    ],
    'script' => [
        'https://scripts.cdn.net'
    ],
);

$myotherCSP = array(
    'base' => 'self'
);

$whoopsIforgotThisCSP = array(
    'form' => 'none'
);

$this->csp($myCSP, 'script', 'https://other.cdn.com', ['block-all-mixed-content'], 'img', 'https://images.cdn.xyz', $myotherCSP);
$this->csp('style', 'https://amazingstylesheets.cdn.pizza', $whoopsIforgotThisCSP, 'upgrade-insecure-requests');
```

## More on Usage
*This section of the README is a work in progress... and is probably very incomplete. Please refer to the source code, or the examples given above for feature highlights*

e.g. the following will combine `$baseCSP` with `$csp` to create an overall Content-Security-Policy.
```php
$headers = new SecureHeaders();

$baseCSP = array(
  "default-src" => ["'self'"]
);
$headers->csp($baseCSP);

# csp_allow_nonce will return the nonce value
# and will add the nonce to the specified directive

$style_nonce = $this->csp_allow_nonce('style');
$script_nonce = $this->csp_allow_nonce('script');

$csp = array(
  "frame-src" => ["https://www.example.com/"],
);

$headers->csp($csp);

$headers->done();
```

The `SecureHeaders` class can also be extended, so that custom settings can be applied on all instances of the extension.
e.g. `$baseCSP` on all pages.

```php
class CustomSecureHeaders extends SecureHeaders{
    public function __construct()
    {
        $this->csp($this->base);
    }
    private $base = array(
        "default-src" => ["'self'"],
        "style-src" => [
            "'self'",
            "https://fonts.googleapis.com/",
            "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/"
        ]
    );
    
}
```

```php
$headers = new CustomSecureHeaders();

# csp_allow_nonce will return the nonce value
# and will add the nonce to the specified directive

$style_nonce = $this->csp_allow_nonce('style');
$script_nonce = $this->csp_allow_nonce('script');

$pageSpecificCSP = array(
    "frame-src" => ["https://www.example.com/"],
);

$headers->csp($pageSpecificCSP);

$headers->done();
```

etc...

*(section nowhere close to complete)*

This readme is incomplete, please refer to the source, or the (non-exhaustive) example file `CustomSecureHeaders.php` for full usage.


#### TODO
* HPKP reporting
* ~~Basic CSP analysis, and warnings when policy apprears unsafe~~
* Import hsts and hpkp policies, reconfigure safemode to use maximums only (do not remove manually set headers, but modify them if unsafe)
