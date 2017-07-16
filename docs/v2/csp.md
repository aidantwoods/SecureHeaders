## Description
```php
void csp ( mixed $csp1 [, mixed $... ] )
```

`->csp()` is used to add and combine various CSP directives, sources, flags, and modes.

The `->csp()` function supports [friendly names](friendly_directives_and_sources)!

## Parameters
### csp
The exact interpretation of `csp` is type dependent.

#### Array
A policy can be passed as an array. The syntax for which is as follows:
```php
$csp = array(
    'directive-variant-1' => 'single-source',
    'directive-variant-2' => array('source1', 'source2'),
    'csp-flag-variant-1'  => null,
    'csp-flag-variant-2',
    'csp-flag-variant-3'  => array(null),
    'empty-directive'     => array()
);
$headers->csp($csp);
```

#### String
Perhaps more convenient for shorter policies, directives and values, or flags can be passed as ordered pairs of strings. The syntax as follows.
```php
$headers->csp('directive-1', 'source', 'directive-2', 'source');
$headers->csp('directive-3', 'source');
$headers->csp('csp-flag-1', null);
$headers->csp('csp-flag-2');
```
Note that only one source may be passed per ordered pair, and a flag must either have null as a source, or have a non-string as its pair (nothing following is okay too).

For example, two csp flags could be declared in any of the following ways (where `$csp` is a csp array).
```php
$headers->csp('flag-1', null, 'flag-2');

$headers->csp('flag-1');
$headers->csp('flag-2');

$headers->csp('flag-1', $csp, 'flag-2')
```

Though the final variant is non-ambiguous to SecureHeaders because it knows the type of `$csp`, it isn't the most readable of methods – someone reading the code may mistake `$csp` to be a string source value for `flag-1`. Though, because it is non-ambiguous it is still an accepted method.

#### Boolean
Passing the boolean `true` will put `csp` into report only mode for the following arguments (meaning that the browser will be told not to enforce anything in the argument list, but will report violations in the browser console, and will send reports to a reporting address if specified). Similarly, passing the boolean `false` will lock the mode of the current call of the `csp` function to being enforced.

If more that one boolean is present, the first will be taken as the mode, and subsequent booleans will be ignored.

Note that report only mode can also be achieved using [`cspro`](cspro), which does not support its mode being changed to enforced.

#### Integer
Integers don't currently have a declared function. For now, they will be loosely casted as booleans and treated as above (meaning that an integer preceding a boolean will lock the mode of `csp`).

In future integers may be used to pass settings via bitwise operators, so take this functionality as a convenience for now which is subject to change. **If you don't plan on reading the changelog between updates, then stay away from using integers to set the reporting mode of the `csp` function, as behaviour may change in the future.**

## Using CSP

If you're new to Content-Security-Policy then running your proposed policy
through [Google's CSP Evaluator](https://csp-evaluator.withgoogle.com/) may be
a good idea.

Let's take a look at a few ways of declaring the following CSP (or parts of
it). Newlines and indentation added here for readability
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

In the above, we've specified the policy using an array in the way it makes the
most sense (bar some slight variation to demonstrate supported syntax).
We then passed our policy array to the `csp` function.

Within the array, take a look at `default-src`. This is the full directive name
(the key of the array), and its source list is specified as an array containing
source values. In this case, the directive only has one source value, `'self'`,
which is spelled out in full (note the single quotes within the string).

In this case, we've actually written a lot more than necessary – see the
directive `base` for comparison. The actual CSP directive here is `base-uri`,
but `base` is a supported shorthand by SecureHeaders. Secondly, we've omitted
the array syntax from the descending source list entirely – we only wanted to
declare one valid source, so SecureHeaders supports foregoing the array
structure if its not useful. Additionally, we've made use of a shorthand within
the source value too – omitting the single quotes from the string's value (i.e.
`self` is a shorthand for `'self'`).

There are two CSP 'flags' included also in this policy, namely
`upgrade-insecure-requests` and `block-all-mixed-content`. These do not hold
any source values (and would not be valid in CSP if they did). You can specify
these by either giving a source value of `null` (either as above, or an array
containing only null as a source), or forgoing any mention of decedents
entirely (as shown in `block-all-mixed-content`, which is written as-is).
Once a flag has been set, no sources may be added. Similarly once a directive
has been set, it may not become a flag. (This to prevent accidental loss of the
entire source list).

The `csp` function also supports combining these CSP arrays, so the following
would combine the csp defined in `$myCSP`, and `$myOtherCSP`. You can combine
as many csp arrays as you like by adding additional arguments.

```php
$headers->csp($myCSP, $myOtherCSP);
```

#### CSP as ordered pairs
Using the same `csp` function as above, you can add sources to directives as
follows
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
Note that the second way is necessary if embedded in a list of ordered pairs –
otherwise SecureHeaders can't tell what is a directive name or a source value.
e.g. this would set `block-all-mixed-content` as a CSP flag, and
`https://my.cdn.org` as a script-src source value.
```php
$headers->csp('block-all-mixed-content', null, 'script', 'https://my.cdn.org');
```

**However**, the `csp` function also supports mixing these ordered pairs with
the array structure, and a string without a source at the end of the argument
list will also be treated as a flag. You could,
*in perhaps an abuse of notation*, use the following to set two CSP flags and
the policy contained in the `$csp` array structure.

```php
$headers->csp('block-all-mixed-content', $csp, 'upgrade-insecure-requests');
```

#### CSP as, uhh..
The CSP function aims to be as tolerant as possible, a CSP should be able to be
communicated in whatever way is easiest to you.

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

$headers->csp(
    $myCSP, 'script', 'https://other.cdn.com',
    ['block-all-mixed-content'], 'img',
    'https://images.cdn.xyz', $myotherCSP
);
$headers->csp(
    'style', 'https://amazingstylesheets.cdn.pizza',
    $whoopsIforgotThisCSP, 'upgrade-insecure-requests'
);
```

#### Behaviour when a CSP header has already been set
```php
header("Content-Security-Policy: default-src 'self'; script-src http://insecure.cdn.org 'self'");
$headers->addHeader(
    'Content-Security-Policy',
    "block-all-mixed-content; img-src 'self' https://cdn.net"
);
$headers->csp('script', 'https://another.domain.example.com');
```

The above code will perform a merge on the two set CSP headers, and will also
merge in the additional `script-src` value set in the final line. Producing
the following merged CSP header
```
Content-Security-Policy:block-all-mixed-content; img-src 'self' https://cdn.net;
script-src https://another.domain.example.com http://insecure.cdn.org 'self';
default-src 'self';
```

This merge capability is fully supported by `->addHeader` (so that if two
calls to add header are made – the CSPs will be extracted and merged).

However, because `header` is part of PHP, this will continue to behave as
normal (i.e. overwrite the last header if called again). Because of this, only
the last called CSP within `header` can be merged with with any additions to
the CSP.

#### Content-Security-Policy-Report-Only
All of the above is applicable to report only policies in exactly the same way.
To tell SecureHeaders that you're creating a report only policy, simply use
[`->cspro`](cspro) in place of `->csp`.

As an alternate method, you can also include the boolean `true`, or a non zero
integer (loosely compares to `true`) in the regular `->csp` function's argument
list. The boolean `false` or the integer zero will signify enforced CSP
(already the default). The left-most of these booleans or intgers will be taken
as the mode. So to force enforced CSP (in-case you are unsure of the eventual
variable types in the CSP argument list), use
`->csp(false, arg1[, arg2[, ...]])` etc... or use zero in place of `false`.
Similarly, to force report-only (in-case you are unsure of the eventual
variable types in the CSP argument list) you can use either
`->cspro(arg1[, arg2[, ...]])` or `->csp(true, arg1[, arg2[, ...]])`.

Note that while `->csp` supports having its mode changed to report-only,
`->cspro` does not (since is an alias for `->csp` with report-only forced on).
`->csp` and `->cspro` are identical in their interpretation of the various
structures a Content-Security-Policy can be communicated in.
