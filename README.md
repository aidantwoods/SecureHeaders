# SecureHeaders
A PHP class aiming to make the use of browser security features more accessible.

## What is a 'secure header'?
Secure headers, are a [set of headers](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#tab=Headers) that configure browser security features. All of these headers can be used in any web application, and most can be deployed without any, or very minor code changes. However some of the most effective ones *do* require code changes – especially to implement well.

## Development Notice
This project is currently under initial development, so there is the potential for non-backwards compatible changes etc.. That said, bug reports are still welcome from anyone who wants to test it out.

## Features
* Add/remove and manage headers easily
* Build a Content Security Policy, or combine multiple together
* Content Security Policy analysis
* Protect incorrectly set cookies
* Safe mode prevents accidental long-term self-DOS when using HSTS, or HPKP
* Receive warnings about missing, or misconfigured security headers

## Methodology and Philosophy
Error messages are often a great way for a program to tell the programmer that something is wrong. Whether it's calling a variable that's not yet been assigned, or causing a fatal error by exhausting the memory allocation limit.

Both of these situations can usually be rectified very quickly by the programmer. The effort required to do so is greatly reduced because the program communicated exactly what the problem was, as soon as the programmer introduced the bug. SecureHeaders aims to apply this concept to browser security features.

Utilising the error reporting level set within PHP configuration, SecureHeaders will generate `E_USER_WARNING` and `E_USER_NOTICE` level error messages to inform the programmer about either misconfigurations or lack of configuration.

In addition to error reporting, SecureHeaders will make some **safe** proactive changes to certain headers, or even add new ones if they're missing. 

## Sounds good, but let's see some of the code...
Here is a good implementation example
```php
$headers = new SecureHeaders();
$headers->hsts();
$headers->csp('default', 'self');
$headers->csp('script', 'https://my.cdn.org');
$headers->done();
```

These few lines of code will take an application from a grade F, to a grade A on Scott Helme's https://securityheaders.io/

## Woah, that was easy! Tell me what it did...
Let's break down the example above.

'Out of the box', SecureHeaders will already do quite a lot (by running the following code)
```php
$headers = new SecureHeaders();
$headers->done();
```

#### Automatic Headers and Errors

With such code, the following will occur:
* Warnings will be issued (`E_USER_WARNING`)
  > **Warning:** Missing security header: 'Strict-Transport-Security'

  > **Warning:** Missing security header: 'Content-Security-Policy'

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

#### Cookies

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

These flags were inserted by SecureHeaders because the cookie name contained the substring `auth`. Of course if that was a bad assumption, you can correct SecureHeaders' behaviour, or conversely you can tell SecureHeaders about some of your cookies that have less obvious names – but may need protecting in case of accidental missing flags.

Let's take a look at those other three lines, the first of which was 
```php
$headers->hsts();
```
This enabled HSTS (Strict-Transport-Security) on the application for a duration of 1 year.

*That sounds like something that might break things – I wouldn't want to accidentally enable that.* 

#### Safe Mode

Okay, SecureHeaders has got you covered – use `$headers->safe_mode();` to prevent headers being sent that will cause lasting effects.

So for example, if the following code was run (safe mode can be called at any point before `->done()` to be effective)
```php
$headers->hsts();
$headers->safe_mode();
```
HSTS would still be enabled (as asked), but would be limited to lasting 24 hours.
SecureHeaders would also generate the following notice

> **Notice:** HSTS settings were overridden because Safe-Mode is enabled. [Read about](https://scotthelme.co.uk/death-by-copy-paste/#hstsandpreloading) some common mistakes when setting HSTS via copy/paste, and ensure you [understand the details](https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet) and possible side effects of this security feature before using it.

*What if I set it via a method not related to SecureHeaders? Can SecureHeaders still enforce safe mode?*

Yup! SecureHeaders will look at the names and values of headers independently of its own built in functions that can be used to generate them.

For example, if I use PHPs built in header function to set HSTS for 1 year, for all subdomains, and indicate consent to preload that rule into major browsers, and then (before or after setting that header) enable safe-mode...

```php
header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
$headers->safe_mode();
```

The same above notice will be generated, max-age will be modified to 1 day, and the preload and includesubdomains flags will be removed. 

#### Content Security Policy

The final two lines to cover from the initial example are as follows
```php
$headers->csp('default', 'self');
$headers->csp('script', 'https://my.cdn.org');
```
These tell SecureHeaders that it should build a CSP (Content Security Policy) that allows default assets to be loaded from the current domain (self), and that scripts should be allowed from https://my.cdn.org.

Note that if we had said http://my.cdn.org instead, then the following would have been generated

> **Warning:** Content Security Policy contains the insecure protocol HTTP in a source value **http://my.cdn.org**; this can allow anyone to insert elements covered by the **script-src** directive into the page.

Similarly, if wildcards such as `'unsafe-inline'`, `https:`, or `*` are included – SecureHeaders will generate warnings to highlight these CSP bypasses.

Note that the `->csp` function is very diverse in what it will accept, to see some more on that take a look at [Using CSP](#using-csp)

## Sending the headers
In order to apply anything added through SecureHeaders, you'll need to call `->done()`. By design, SecureHeaders doesn't have a construct function – so everything up until `->done()` is called is just configuration. However, if you don't want to have to remember to call this function, you can call `->done_on_output()` instead, at any time. This will utilise PHP's `ob_start()` function to start output buffering. This lets SecureHeaders attatch itself to the first instance of any piece of code that generates output – and prior to actually sending that output to the user, make sure all headers are sent, by calling `->done()` for you.

Because SecureHeaders doesn't have a construct function, you can easily implement your own, via a simple class extension, e.g.
```php
class CustomSecureHeaders extends SecureHeaders{
    public function __construct()
    {
        $this->done_on_output();
        $this->hsts();
        $this->csp('default', 'self');
        $this->csp('script', 'https://my.cdn.org');
    }
}
```

The above would implement the example discussed above, and would automatically apply to any page that ran just one line of code
```php
$headers = new CustomSecureHeaders();
```

Of course, pages could add additional configuration too, and headers would only be applied when the page started generating output.


## Another Example

If the following CSP is created (note this probably isn't the best way to define a CSP of this size, see the array syntax that is available in the section on [Using CSP](#using-csp))

```php
$headers->csp('default', '*');
$headers->csp('script', 'unsafe-inline');
$headers->csp('script', 'http://insecure.cdn.org');
$headers->csp('style', 'https:');
$headers->csp('style', '*');
$headers->csp('report', 'https://valid-enforced-url.org');
$headers->cspro('report', 'whatisthis');
```

```
Content-Security-Policy:default-src *; script-src 'unsafe-inline' http://insecure.cdn.org; style-src https: *; report-uri https://valid-enforced-url.org;
Content-Security-Policy-Report-Only:report-uri whatisthis;
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

If you're new to Content-Security-Policy then running your proposed policy through [Google's CSP Evaluator](https://csp-evaluator.withgoogle.com/) may be a good idea.

Let's take a look at a few ways of declaring the following CSP (or parts of it). Newlines and indentation added here for readability
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
    'upgrade-insecure-requests' => null,
    'block-all-mixed-content'
);

$headers->csp($myCSP);
```

In the above, we've specified the policy using an array in the way it makes the most sense (bar some slight variation to demonstrate supported syntax).
We then passed our policy array to the `csp` function.

Within the array, take a look at `default-src`. This is the full directive name (the key of the array), and its source list is specified as an array containing source values. In this case, the directive only has one source value, `'self'`, which is spelled out in full (note the single quotes within the string).

In this case, we've actually written a lot more than necessary – see the directive `base` for comparison. The actual CSP directive here is `base-uri`, but `base` is a supported shorthand by SecureHeaders. Secondly, we've omitted the array syntax from the descending source list entirely – we only wanted to declare one valid source, so SecureHeaders supports foregoing the array structure if its not useful. Additionally, we've made use of a shorthand within the source value too – omitting the single quotes from the string's value (i.e. `self` is a shorthand for `'self'`).

There are two CSP 'flags' included also in this policy, namely `upgrade-insecure-requests` and `block-all-mixed-content`. These do not hold any source values (and would not be valid in CSP if they did). You can specify these by either giving a source value of `null` (either as above, or an array containing only null as a source), or forgoing any mention of decedents entirely (as shown in `block-all-mixed-content`, which is written as-is).
Once a flag has been set, no sources may be added. Similarly once a directive has been set, it may not become a flag. (This to prevent accidental loss of the entire source list).

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

**However**, the `csp` function also supports mixing these ordered pairs with the array structure, and a string without a source at the end of the argument list will also be treated as a flag. You could, *in perhaps an abuse of notation*, use the following to set two CSP flags and the policy contained in the `$csp` array structure.

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

$headers->csp($myCSP, 'script', 'https://other.cdn.com', ['block-all-mixed-content'], 'img', 'https://images.cdn.xyz', $myotherCSP);
$headers->csp('style', 'https://amazingstylesheets.cdn.pizza', $whoopsIforgotThisCSP, 'upgrade-insecure-requests');
```

#### Behaviour when a CSP header has already been set
```php
header("Content-Security-Policy: default-src 'self'; script-src http://insecure.cdn.org 'self'");
$headers->add_header('Content-Security-Policy', "block-all-mixed-content; img-src 'self' https://cdn.net");
$headers->csp('script', 'https://another.domain.example.com');
```

The above code will perform a merge on the two set CSP headers, and will also merge in the additional `script-src` value set in the final line. Producing the following merged CSP header
```
Content-Security-Policy:block-all-mixed-content; img-src 'self' https://cdn.net; script-src https://another.domain.example.com http://insecure.cdn.org 'self'; default-src 'self';
```

This merge capability is fully supported by `->add_header` (so that if two calls to add header are made – the CSPs will be extracted and merged). 

However, because `header` is part of PHP, this will continue to behave as normal (i.e. overwrite the last header if called again). Because of this, only the last called CSP within `header` can be merged with with any additions to the CSP.

#### Content-Security-Policy-Report-Only
All of the above is applicable to report only policies in exactly the same way. To tell SecureHeaders that you're creating a report only policy, simply use `->cspro` in place of `->csp`.

As an alternate method, you can also include the boolean `true`, or a non zero integer (loosely compares to `true`) in the regular `->csp` function's argument list. The boolean `false` or the integer zero will signify enforced CSP (already the default). The left-most of these booleans or intgers will be taken as the mode. So to force enforced CSP (in-case you are unsure of the eventual variable types in the CSP argument list), use `->csp(false, arg1[, arg2[, ...]])` etc... or use zero in place of `false`. Similarly, to force report-only (in-case you are unsure of the eventual variable types in the CSP argument list) you can use either `->cspro(arg1[, arg2[, ...]])` or `->csp(true, arg1[, arg2[, ...]])`.

Note that while `->csp` supports having its mode changed to report-only, `->cspro` does not (since is an alias for `->csp` with report-only forced on). `->csp` and `->cspro` are identical in their interpretation of the various structures a Content-Security-Policy can be communicated in.

## More on Usage
*This section of the README is a work in progress... and is probably very incomplete. Please refer to the source code, or the examples given above for feature highlights*

e.g. the following will combine `$baseCSP` with `$csp` to create an overall Content-Security-Policy.
```php
$headers = new SecureHeaders();

$baseCSP = array(
  "default-src" => 'self'
);
$headers->csp($baseCSP);

# csp_allow_nonce will return the nonce value
# and will add the nonce to the specified directive

$style_nonce = $headers->csp_nonce('style');
$script_nonce = $headers->csp_nonce('script');

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
        "default-src" => 'self',
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

$style_nonce = $headers->csp_nonce('style');
$script_nonce = $headers->csp_nonce('script');

$pageSpecificCSP = array(
    "frame-src" => "https://www.example.com/",
);

$headers->csp($pageSpecificCSP);

$headers->done();
```

etc...

*(section nowhere close to complete)*

This readme is incomplete, please refer to the source, or the (non-exhaustive) example file `CustomSecureHeaders.php` for full usage.
