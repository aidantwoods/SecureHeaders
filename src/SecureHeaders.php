<?php

namespace Aidantwoods\SecureHeaders;

#
# SecureHeaders
# https://github.com/aidantwoods/SecureHeaders
#
# ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~
#
# MIT License
#
# Copyright (c) 2016-2017 Aidan Woods
# https://aidanwoods.com
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the "Software"),
# to deal in the Software without restriction, including without limitation
# the rights to use, copy, modify, merge, publish, distribute, sublicense,
# and/or sell copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
#

use Aidantwoods\SecureHeaders\Http\GlobalHttpAdapter;
use Aidantwoods\SecureHeaders\Http\HttpAdapter;
use Aidantwoods\SecureHeaders\Operations\AddHeader;
use Aidantwoods\SecureHeaders\Operations\ApplySafeMode;
use Aidantwoods\SecureHeaders\Operations\CompileCSP;
use Aidantwoods\SecureHeaders\Operations\CompileExpectCT;
use Aidantwoods\SecureHeaders\Operations\CompileHPKP;
use Aidantwoods\SecureHeaders\Operations\CompileHSTS;
use Aidantwoods\SecureHeaders\Operations\InjectStrictDynamic;
use Aidantwoods\SecureHeaders\Operations\ModifyCookies;
use Aidantwoods\SecureHeaders\Operations\RemoveHeaders;
use Aidantwoods\SecureHeaders\Operations\RemoveCookies;
use Aidantwoods\SecureHeaders\Util\Types;

class SecureHeaders
{

    # ~~
    # Version

    const version = '2.0.0';

    # ~~
    # protected variables: settings

    protected $errorReporting           = true;

    protected $cspLegacy                = false;
    protected $returnExistingNonce      = true;

    protected $strictMode               = false;

    protected $safeMode                 = false;
    protected $safeModeExceptions       = [];

    protected $automaticHeaders         = self::AUTO_ALL;

    protected $sameSiteCookies          = null;

    protected $reportMissingExceptions  = [];

    protected $protectedCookies = [
        'substrings'    => [
            'sess',
            'auth',
            'login',
            'csrf',
            'xsrf',
            'token',
            'antiforgery'
        ],
        'names'         => [
            'sid',
            's',
            'persistent'
        ]
    ];

    protected $headerProposals = [
        'Expect-CT'
            => 'max-age=0',
        'Referrer-Policy'
            => [
                'no-referrer',
                'strict-origin-when-cross-origin'
            ],
        'X-Permitted-Cross-Domain-Policies'
            => 'none',
        'X-XSS-Protection'
            => '1; mode=block',
        'X-Content-Type-Options'
            => 'nosniff',
        'X-Frame-Options'
            => 'Deny'
    ];

    # ~~
    # private variables: (non settings)

    private $removedHeaders     = [];

    private $removedCookies     = [];

    private $errors             = [];
    private $errorString;

    private $csp                = [];
    private $cspro              = [];

    private $cspNonces          = [
        'enforced'      =>  [],
        'reportOnly'    =>  []
    ];

    private $expectCT           = [];

    private $hsts               = [];

    private $hpkp               = [];
    private $hpkpro             = [];

    private $isBufferReturned   = false;

    private $applyOnOutput      = null;

    # private variables: (pre-defined static structures)

    private $cspDirectiveShortcuts  = [
        'default'           =>  'default-src',
        'script'            =>  'script-src',
        'style'             =>  'style-src',
        'image'             =>  'img-src',
        'img'               =>  'img-src',
        'font'              =>  'font-src',
        'child'             =>  'child-src',
        'base'              =>  'base-uri',
        'connect'           =>  'connect-src',
        'form'              =>  'form-action',
        'object'            =>  'object-src',
        'report'            =>  'report-uri',
        'reporting'         =>  'report-uri'
    ];

    private $cspSourceShortcuts     = [
        'self'              =>  "'self'",
        'none'              =>  "'none'",
        'unsafe-inline'     =>  "'unsafe-inline'",
        'unsafe-eval'       =>  "'unsafe-eval'",
        'strict-dynamic'    =>  "'strict-dynamic'"
    ];

    protected $csproBlacklist       = [
        'block-all-mixed-content',
        'upgrade-insecure-requests'
    ];

    private $allowedCSPHashAlgs     = [
        'sha256',
        'sha384',
        'sha512'
    ];

    private $allowedHPKPAlgs        = [
        'sha256'
    ];

    private $reportMissingHeaders   = [
        'Expect-CT',
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Permitted-Cross-Domain-Policies',
        'X-XSS-Protection',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'Referrer-Policy'
    ];

    # ~
    # Constants

    # auto-headers

    const AUTO_ADD              = 0b00001;
    const AUTO_REMOVE           = 0b00010;
    const AUTO_COOKIE_SECURE    = 0b00100;
    const AUTO_COOKIE_HTTPONLY  = 0b01000;
    const AUTO_COOKIE_SAMESITE  = 0b10000;
    const AUTO_ALL              = 0b11111;

    # cookie upgrades

    const COOKIE_NAME           = 0b00001;
    const COOKIE_SUBSTR         = 0b00010;
    const COOKIE_ALL            = 0b00011; # COOKIE_NAME | COOKIE_SUBSTR
    const COOKIE_REMOVE         = 0b00100;
    const COOKIE_DEFAULT        = 0b00010; # ~COOKIE_REMOVE & COOKIE_SUBSTR

    # ~~
    # Public Functions

    /**
     * Used to enable or disable output buffering with ob_start.
     * When enabled, the ob_start callback will be set to automatically call
     * {@see apply} upon the first byte of output.
     *
     * If unconfigured, the default setting for {@see applyOnOutput} is off.
     *
     * @api
     *
     * @param HttpAdapter $http
     * @param mixed $mode
     *  mode is the on/off setting. Any value of type that is loosely castable to a boolean is valid.
     *
     *  Passing a boolean of value true will turn output buffering on,
     *  passing a boolean of value false will turn it off. The integers
     *  1 and 0 will do the same respectively.
     *
     * @return void
     */
    public function applyOnOutput(HttpAdapter $http = null, $mode = true)
    {
        if ($mode == true)
        {
            if ($this->applyOnOutput === null)
            {
                ob_start([$this, 'returnBuffer']);
            }

            $this->applyOnOutput = $http;
        }
        elseif ($this->applyOnOutput !== null)
        {
            ob_end_clean();

            $this->applyOnOutput = null;
        }
    }

    # ~~
    # public functions: settings

    # ~~
    # Settings: Safe Mode

    /**
     * Used to turn safe mode on or off.
     *
     * Safe mode will modify certain headers that may cause lasting effects so
     * to limit how long accidental effects can last for.
     *
     * Note that exceptions can be made to safe-mode on a header by header
     * basis with {@see safeModeException}
     *
     * @api
     *
     * @param mixed $mode
     *  mode is the on/off setting. Any value of type that is loosely castable to a boolean is valid.
     *
     *  Loosely casted to a boolean, `true` turns safe mode on, `false` turns
     *  it off. The exception being the string 'off' case-insensitively, which
     *  will operate as if it was casted to `false` (this makes the behaviour
     *  more similar to the way some values are set in PHP ini files).
     *
     * @return void
     */
    public function safeMode($mode = true)
    {
        $this->safeMode = ($mode == true and strtolower($mode) !== 'off');
    }

    /**
     * Used to add an exception to {@see safeMode}.
     *
     * @api
     *
     * @param string $name
     *  Specify the name of the header that you wish to be exempt from
     *  {@see safeMode} warnings and auto-modification.
     *
     *  (Note that if you want to turn safe mode off for all headers, use
     *  [`->safeMode(false)`](safeMode) – safe mode is **not** on by default).
     *
     * @return void
     */
    public function safeModeException($name)
    {
        Types::assert(['string' => [$name]]);

        $this->safeModeExceptions[strtolower($name)] = true;
    }

    # ~~
    # Settings: Strict Mode

    /**
     * Turn strict mode on or off.
     *
     * When enabled, strict mode will:
     * * Auto-enable HSTS with a 1 year duration, and the `includeSubDomains`
     *   and `preload` flags set. Note that this HSTS policy is made as a
     *   [header proposal](header-proposals), and can thus be removed or
     *   modified.
     *
     * * The source keyword `'strict-dynamic'` will also be added to the first
     *   of the following directives that exist: `script-src`, `default-src`;
     *   only if that directive also contains a nonce or hash source value, and
     *   not otherwise.
     *
     *   This will disable the source whitelist in `script-src` in CSP3
     *   compliant browsers. The use of whitelists in script-src is
     *   [considered not to be an ideal practice][1], because they are often
     *   trivial to bypass.
     *
     *   [1]: https://research.google.com/pubs/pub45542.html "The Insecurity of
     *   Whitelists and the Future of Content Security Policy"
     *
     *   Don't forget to [manually submit](https://hstspreload.appspot.com/)
     *   your domain to the HSTS preload list if you are using this option.
     *
     * * The default `SameSite` value injected into {@see protectedCookie} will
     *   be changed from `SameSite=Lax` to `SameSite=Strict`.
     *   See [`->auto`](auto#AUTO_COOKIE_SAMESITE) to enable/disable injection
     *   of `SameSite` and {@see sameSiteCookies} for more on specific behaviour
     *   and to explicitly define this value manually, to override the default.
     *
     * * Auto-enable Expect-CT with a 1 year duration, and the `enforce` flag
     *   set. Note that this Expect-CT policy is made as a
     *   [header proposal](header-proposals), and can thus be removed or
     *   modified.
     *
     * @api
     *
     * @param mixed $mode
     *  Loosely casted to a boolean, `true` enables strict mode, `false` turns
     *  it off.
     *
     * @return void
     */
    public function strictMode($mode = true)
    {
        $this->strictMode = ($mode == true and strtolower($mode) !== 'off');
    }

    # ~~
    # Settings: Error Reporting

    /**
     * Enable or disable error reporting.
     *
     * Note that SecureHeaders will honour the PHP configuration for error
     * reporting level and for whether errors are displayed by default. If you
     * would like to specifically turn off errors from only SecureHeaders then
     * use this function.
     *
     * @api
     *
     * @param mixed $mode
     *  Loosely casted as a boolean, `true` will enable error reporting
     *  (the default), `false` will disable it.
     *
     * @return void
     */
    public function errorReporting($mode)
    {
        $this->errorReporting = ($mode == true);
    }

    /**
     *
     * Selectively disable 'Missing security header: ...' reports for a
     * specific header.
     *
     * @api
     *
     * @param string $name
     *  The (case-insensitive) name of the header to disable missing reports
     *  for.
     *
     * @return void
     */
    public function reportMissingException($name)
    {
        Types::assert(['string' => [$name]]);

        $this->reportMissingExceptions[strtolower($name)] = true;
    }

    # ~~
    # Settings: Automatic Behaviour

    /**
     * Enable or disable certain automatically applied header functions
     *
     * If unconfigured, the default setting for {@see auto} is
     * {@see AUTO_ALL}.
     *
     * @api
     *
     * @param int $mode
     *  `mode` accepts one or more of the following constants. Multiple
     *  constants may be specified by combination using
     *  [bitwise operators](https://secure.php.net/manual/language.operators.bitwise.php)
     *
     * @return void
     */
    public function auto($mode = self::AUTO_ALL)
    {
        Types::assert(['int' => [$mode]]);

        $this->automaticHeaders = $mode;
    }

    # ~~
    # Settings: Nonces

    /**
     * Determine the behaviour of {@see cspNonce} and its aliases when
     * a nonce for the specified directive already exists.
     *
     * When enabled, the existing nonce will be returned. When disabled, a new
     * nonce will be generated for the directive, added alongside the existing
     * one, and the new nonce will be returned.
     *
     * If not explicitly set, the default mode for this setting is enabled.
     *
     * @api
     *
     * @param mixed $mode
     *  Loosely casted to a boolean, `true` enables the behaviour, `false`
     *  turns it off.
     *
     * @return void
     */
    public function returnExistingNonce($mode = true)
    {
        $this->returnExistingNonce = ($mode == true);
    }

    # ~~
    # Settings: Cookies

    /**
     * Add and configure the default setting for
     * [protected cookies](protectedCookie) that are automatically marked
     * as `SameSite`.
     *
     * If this setting is unspecified the default will be `SameSite=Lax`, if
     * this setting is given an invalid `string` setting the last setting will
     * be honoured. If {@see strictMode} is enabled then the default
     * will be `SameSite=Strict` under the same criteria for set value. If you
     * wish to disable making cookies as same site,
     * see [`->auto`](auto#AUTO_COOKIE_SAMESITE).
     *
     * @api
     *
     * @param string $mode
     *  Valid values for `$mode` are either (case-insensitively) the strings
     *  `'Lax'` and `'Strict'`. If `null` is passed the setting will revert to
     *  the default as defined above. If another `string` is passed then the
     *  call will be ignored and the previous setting will be retained (if no
     *  setting was specified previously then the default will remain).
     *
     * @return void
     */
    public function sameSiteCookies($mode = null)
    {
        Types::assert(['string' => [$mode]]);

        if (isset($mode))
        {
            $mode = strtolower($mode);
        }

        if ($mode === 'lax' or $mode === 'strict')
        {
            $this->sameSiteCookies = ucfirst($mode);
        }
        elseif ( ! isset($mode))
        {
            $this->sameSiteCookies = null;
        }
    }

    # ~~
    # public functions: raw headers

    /**
     * Queue a header for removal.
     *
     * Upon calling {@see apply} the header will be removed. This function can
     * be used to manually prevent [automatic headers](auto) from being sent.
     *
     * @api
     *
     * @param string $name
     *  Case insensitive name of the header to remove.
     *
     * @return void
     */
    public function removeHeader($name)
    {
        Types::assert(['string' => [$name]]);

        $name = strtolower($name);
        $this->removedHeaders[$name] = true;
    }

    # ~~
    # public functions: cookies

    /**
     * Configure which cookies SecureHeaders will regard as protected.
     *
     * SecureHeaders will consider substrings and names of cookies separately.
     * By default, cookies that case insensitively match the following
     * substrings or names will be regarded as protected.
     *
     * #### Substrings
     * ```
     * sess
     * auth
     * login
     * csrf
     * xsrf
     * token
     * antiforgery
     * ```
     *
     * #### Names
     * ```
     * sid
     * s
     * persistent
     * ```
     *
     * If a cookie is protected, then cookie flags will be appended as
     * configured by {@see auto}. The default behaviour is to add `Secure` and
     * `HttpOnly` flags, to ensure cookies are both sent securely, and out of
     * the reach of JavaScript.
     *
     * @api
     *
     * @param string|array $name
     *  The name (or substring of the name, depending on mode configuration),
     *  of the cookie to add/remove from the protection list (depending on mode
     *  configuration). Or a list of cookie names (or substrings of the name to
     *  match) as an array of strings.
     * @param int $mode
     *  `mode` accepts one or more of the following constants. Multiple
     *   constants may be specified by combination using
     *  [bitwise operators](https://secure.php.net/manual/language.operators.bitwise.php)
     *
     * @return void
     */
    public function protectedCookie(
        $name,
        $mode = self::COOKIE_DEFAULT
    ) {
        Types::assert(
            [
                'string|array' => [$name],
                'int' => [$mode]
            ]
        );

        if (is_string($name))
        {
            $name = strtolower($name);
        }
        elseif (is_array($name))
        {
            foreach ($name as $cookie)
            {
                $this->protectedCookie($cookie, $mode);
            }
            return;
        }

        $stringTypes = [];

        if (($mode & self::COOKIE_NAME) === self::COOKIE_NAME)
        {
            $stringTypes[] = 'names';
        }

        if (($mode & self::COOKIE_SUBSTR) === self::COOKIE_SUBSTR)
        {
            $stringTypes[] = 'substrings';
        }

        foreach ($stringTypes as $type)
        {
            if (
                ($mode & self::COOKIE_REMOVE) !== self::COOKIE_REMOVE
            and ! in_array($name, $this->protectedCookies[$type])
            ) {
                $this->protectedCookies[$type][] = $name;
            }
            elseif (
                ($mode & self::COOKIE_REMOVE) === self::COOKIE_REMOVE
                and (
                    $key = array_search(
                        $name,
                        $this->protectedCookies[$type]
                    )
                ) !== false
            ) {
                unset($this->protectedCookies[$type][$key]);
            }
        }
    }

    /**
     * Remove a cookie from SecureHeaders' internal list (thus preventing the
     * `Set-Cookie` header for that specific cookie from being sent).
     *
     * This allows you to form a blacklist for cookies that should not be sent
     * (either programatically or globally, depending on where this is
     * configured).
     *
     * @api
     *
     * @param string $name
     *  The (case-insensitive) name of the cookie to remove.
     *
     * @return void
     */
    public function removeCookie($name)
    {
        Types::assert(['string' => [$name]]);

        $this->removedCookies[] = strtolower($name);
    }

    # ~~
    # public functions: Content-Security-Policy (CSP)

    /**
     * @api
     *
     * @ignore Polymorphic variadic function
     */
    public function csp()
    {
        $args = func_get_args();

        Types::assert(['string|array|int|bool' => $args]);

        $num = count($args);

        # look for a bool or intgers (commonly used in place of bools)
        # if one is found the first of which is loosly interpreted as
        # the setting for report only, remaining are ignored
        foreach ($args as $arg)
        {
            if (is_bool($arg) or is_int($arg))
            {
                $reportOnly = ($arg == true);
                break;
            }
        }
        # if no such items can be found, default to enforced csp
        if ( ! isset($reportOnly))
        {
            $reportOnly = false;
        }

        # look at all the arguments
        for ($i = 0; $i < $num; $i++)
        {
            $arg = $args[$i];

            # if the arg is an array, then treat is as an entire policy
            if (is_array($arg))
            {
                $this->cspArray($arg, $reportOnly);
            }
            # if the arg is a string
            elseif (is_string($arg))
            {
                # then the arg is the directive name
                $friendlyDirective = $arg;

                # if we've specified a source value (string: source,
                # or null: directive is flag)
                if (
                    ($i + 1 < $num)
                    and (is_string($args[$i+1]) or is_null($args[$i+1]))
                ) {
                    # then use the value we specified, and skip over the next
                    # item in the loop (since we just used it as a source value)
                    $friendlySource = $args[$i+1];
                    $i++;
                }
                # if no source is specified (either no more args, or one of
                # unsupported type)
                else
                {
                    # assume that the directive is a flag
                    $friendlySource = null;
                }

                $this->cspAllow(
                    $friendlyDirective,
                    $friendlySource,
                    $reportOnly
                );
            }
        }
    }

    /**
     * @api
     *
     * @ignore Polymorphic variadic function
     */
    public function cspro()
    {
        $args = func_get_args();

        Types::assert(['string|array|int|bool' => $args]);

        foreach ($args as $i => $arg)
        {
            if (is_bool($arg) or is_int($arg))
            {
                unset($args[$i]);
            }
        }

        $args = array_values($args);

        array_unshift($args, true);

        call_user_func_array([$this, 'csp'], $args);
    }

    # Content-Security-Policy: Settings

    /**
     * Enable or disable legacy CSP support.
     *
     * When enabled, SecureHeaders will send an additional
     * `X-Content-Security-Policy` and/or
     * `X-Content-Security-Policy-Report-Only`. The policy configured with
     * {@see csp} or {@see cspro} respectively will be sent with this legacy
     * header, with no attempt to strip out newer CSP features (browsers should
     * ignore CSP directives and keywords they do not recognise).
     *
     * If this setting is unconfigured, the default is off.
     *
     * @api
     *
     * @param mixed $mode
     *  Loosely casted as a boolean, `true` enables the legacy headers, `false`
     *  disables them.
     *
     * @return void
     */
    public function cspLegacy($mode = true)
    {
        $this->cspLegacy = ($mode == true);
    }

    # Content-Security-Policy: Policy string removals

    /**
     * Remove a previously added source from a CSP directive.
     *
     * @api
     *
     * @param string $directive
     *  The directive (case insensitive) in which the source to be removed
     *  resides.
     * @param string $source
     *  The source (case insensitive) to remove.
     * @param mixed $reportOnly
     *  Loosely casted as a boolean, `true` ensures the function acts on the
     *  report only policy, `false` (the default, as `null` casts to false)
     *  ensures the function acts on the enforced policy.
     *
     * @return void
     */
    public function removeCSPSource($directive, $source, $reportOnly = null)
    {
        Types::assert(['string' => [$directive, $source]]);

        $csp = &$this->getCSPObject($reportOnly);

        $source = strtolower($source);
        $directive = strtolower($directive);

        if ( ! isset($csp[$directive][$source]))
        {
            return false;
        }

        unset($csp[$directive][$source]);

        return true;
    }

    /**
     * Remove a previously added directive from CSP.
     *
     * @api
     *
     * @param string $directive
     *  The directive (case insensitive) to remove.
     * @param mixed $reportOnly
     *  Loosely casted as a boolean, `true` ensures the function acts on the
     *  report only policy, `false` (the default, as `null` casts to false)
     *  ensures the function acts on the enforced policy.
     *
     * @return void
     */
    public function removeCSPDirective($directive, $reportOnly = null)
    {
        Types::assert(['string' => [$directive]]);

        $csp = &$this->getCSPObject($reportOnly);

        $directive = strtolower($directive);

        if ( ! isset($csp[$directive]))
        {
            return false;
        }

        unset($csp[$directive]);

        return true;
    }

    /**
     * Reset the CSP.
     *
     * @api
     *
     * @param mixed $reportOnly
     *  Loosely casted to a boolean, `true` resets the policy configured by
     * {@see cspro}, `false` resets the policy configured by {@see csp}.
     *
     * @return void
     */
    public function resetCSP($reportOnly = null)
    {
        $csp = &$this->getCSPObject($reportOnly);

        $csp = [];
    }

    # Content-Security-Policy: Hashing

    /**
     * Generate a hash of the provided [`$string`](#string) value, and have it
     * added to the [`$friendlyDirective`](#friendlyDirective) directive in CSP.
     *
     * @api
     *
     * @param string $friendlyDirective
     *  The (case insensitive)
     *  [friendly name](friendly_directives_and_sources#directives) that the
     *  hash should be to be added to.
     * @param string $string
     *  The string that should be hashed and added to the
     *  [`$friendlyDirective`](friendly_directives_and_sources#directives)
     *  directive.
     * @param ?string $algo = 'sha256'
     *  The hashing algorithm to use. CSP currently supports `sha256`,
     *  `sha384`, `sha512`.
     * @param mixed $isFile
     *  Loosely casted as a boolean. Indicates that [`$string`](string) instead
     *  specifies a file path.
     * @param mixed $reportOnly
     *  Loosely casted as a boolean. Indicates that the hash should be added
     *  to the report only policy `true`, or the enforced policy `false`.
     *
     * @return string
     *  Returns the hash value.
     */
    public function cspHash(
        $friendlyDirective,
        $string,
        $algo = null,
        $isFile = null,
        $reportOnly = null
    ) {
        Types::assert(
            ['string' => [$friendlyDirective, $string, $algo]]
        );

        if (
            ! isset($algo)
            or ! in_array(
                strtolower($algo),
                $this->allowedCSPHashAlgs
            )
        ) {
            $algo = 'sha256';
        }

        $hash = $this->cspDoHash($string, $algo, $isFile);

        $hashString = "'$algo-$hash'";

        $this->cspAllow($friendlyDirective, $hashString, $reportOnly);

        return $hash;
    }

    /**
     * An alias for {@see cspHash} with [reportOnly](cspHash#reportOnly)
     * set to true.
     *
     * @api
     *
     * @param string $friendlyDirective
     * @param string $string
     * @param ?string $algo = 'sha256'
     * @param mixed $isFile
     *
     * @return string
     */
    public function csproHash(
        $friendlyDirective,
        $string,
        $algo = null,
        $isFile = null
    ) {
        Types::assert(
            ['string' => [$friendlyDirective, $string, $algo]]
        );

        return $this->cspHash(
            $friendlyDirective,
            $string,
            $algo,
            $isFile,
            true
        );
    }

    /**
     * An alias for {@see cspHash} with [isFile](cspHash#isFile) set to `true`.
     *
     * @api
     *
     * @param string $friendlyDirective
     * @param string $string
     * @param ?string $algo = 'sha256'
     * @param mixed $reportOnly
     *
     * @return string
     */
    public function cspHashFile(
        $friendlyDirective,
        $string,
        $algo = null,
        $reportOnly = null
    ) {
        Types::assert(
            ['string' => [$friendlyDirective, $string, $algo]]
        );

        return $this->cspHash(
            $friendlyDirective,
            $string,
            $algo,
            true,
            $reportOnly
        );
    }

    /**
     * An alias for {@see cspHash} with [reportOnly](cspHash#reportOnly) set
     * to true, and [isFile](cspHash#isFile) set to true.
     *
     * @api
     *
     * @param string $friendlyDirective
     * @param string $string
     * @param ?string $algo = 'sha256'
     *
     * @return string
     */
    public function csproHashFile($friendlyDirective, $string, $algo = null)
    {
        Types::assert(
            ['string' => [$friendlyDirective, $string, $algo]]
        );

        return $this->cspHash($friendlyDirective, $string, $algo, true, true);
    }

    # Content-Security-Policy: Nonce

    /**
     * Used to securely generate a nonce value, and have it be added to the
     * [`$friendlyDirective`](#friendlyDirective) in CSP.
     *
     * Note that if a nonce already exists for the specified directive, the
     * existing value will be returned instead of generating a new one
     * (multiple nonces in the same directive don't offer any security benefits
     * at present – since they're all treated equally). This should facilitate
     * distributing the nonce to any code that needs it (provided the code can
     * access the SecureHeaders instance).
     *
     * If you want to disable returning an existing nonce, use
     * {@see returnExistingNonce} to turn the behaviour on or off.

     * **Make sure not to use nonces where the content given the nonce is
     * partially of user origin! This would allow an attacker to bypass the
     * protections of CSP!**
     *
     * @api
     *
     * @param string $friendlyDirective
     *  The (case insensitive)
     *  [friendly name](friendly_directives_and_sources#directives) that the
     *  nonce should be to be added to.
     * @param mixed $reportOnly
     *  Loosely casted as a boolean. Indicates that the hash should be added to
     *  the report only policy `true`, or the enforced policy `false`.
     *
     * @return string
     *  Returns the nonce value.
     */
    public function cspNonce($friendlyDirective, $reportOnly = null)
    {
        Types::assert(['string' => [$friendlyDirective]]);

        $reportOnly = ($reportOnly == true);

        $nonceStore = &$this->cspNonces[
            ($reportOnly ? 'reportOnly' : 'enforced')
        ];

        $directive = $this->longDirective($friendlyDirective);

        if ($this->returnExistingNonce and isset($nonceStore[$directive]))
        {
            return $nonceStore[$directive];
        }

        $nonce = $this->cspGenerateNonce();

        $nonceString = "'nonce-$nonce'";

        $this->addCSPSource($directive, $nonceString, $reportOnly);

        $nonceStore[$directive] = $nonce;

        return $nonce;
    }

    /**
     * An alias for {@see cspNonce} with [reportOnly](cspNonce#reportOnly)
     * set to true.
     *
     * **Make sure not to use nonces where the content given the nonce is
     * partially of user origin! This would allow an attacker to bypass the
     * protections of CSP!**
     *
     * @api
     *
     * @param string $friendlyDirective
     *
     * @return string
     */
    public function csproNonce($friendlyDirective)
    {
        Types::assert(['string' => [$friendlyDirective]]);

        return $this->cspNonce($friendlyDirective, true);
    }

    # ~~
    # public functions: Expect-CT

    /**
     * Used to add and configure the Expect-CT header.
     *
     * Expect-CT makes sure that a user's browser will fill the role of
     * ensuring that future requests, within $maxAge seconds will have
     * certificate transparancy.
     *
     * If set to enforcement mode, the browser will fail the TLS connection if
     * the certificate transparency requirement is not met
     *
     * @api
     *
     * @param ?int|string $maxAge
     *  The length, in seconds either as a string, or an integer – specify the
     *  length that a user's browser should remember that the application
     *  should be delivered with a certificate transparency expectation.
     *
     * @param ?mixed $enforce
     *  Loosely casted as a boolean, whether to enforce (by failing the TLS
     *  connection) that certificate transparency is enabled for the next
     *  $maxAge seconds, or whether to only report to the console, and to
     *  $reportUri if an address is defined.
     *
     * @param ?string $reportUri
     *  A reporting address to send violation reports to.
     *
     *  Passing `null` indicates that a reporting address should not be modified
     *  on this call (e.g. can be used to prevent overwriting a previous
     *  setting).
     *
     * @return void
     */
    public function expectCT(
        $maxAge    = 31536000,
        $enforce   = true,
        $reportUri = null
    ) {
        Types::assert(
            [
                'int|string' => [$maxAge],
                'string' => [$reportUri]
            ],
            [1, 3]
        );

        if (isset($maxAge) or ! isset($this->expectCT['max-age']))
        {
            $this->expectCT['max-age'] = $maxAge;
        }

        if (isset($enforce) or ! isset($this->expectCT['enforce']))
        {
            $this->expectCT['enforce']
                = (isset($enforce) ? ($enforce == true) : null);
        }

        if (isset($reportUri) or ! isset($this->expectCT['report-uri']))
        {
            $this->expectCT['report-uri'] = $reportUri;
        }
    }

    # ~~
    # public functions: HSTS

    /**
     * Used to add and configure the Strict-Transport-Security header.
     *
     * HSTS makes sure that a user's browser will fill the role of redirecting
     * them from HTTP to HTTPS so that they need not trust an insecure response
     * from the network.
     *
     * @api
     *
     * @param int|string $maxAge
     *  The length, in seconds either as a string, or an integer – specify the
     *  length that a user's browser should remember that the application is
     *  HTTPS only.
     *
     * @param mixed $subdomains
     *  Loosely casted as a boolean, whether to include the `includeSubDomains`
     *  flag – to deploy the HSTS policy across the entire domain.
     *
     * @param mixed $preload
     *  Loosely casted as a boolean, whether to include the `preload` flag – to
     *  consent to have the domain loaded into
     *  [various preload lists](https://hstspreload.appspot.com/) (so that a
     *  user need not initially visit your site securely to know about the
     *  HSTS policy).
     *
     *  You must also [manually preload](https://hstspreload.appspot.com/)
     *  your domain for this to take effect – the flag just indicates consent.
     *
     * @return void
     */
    public function hsts(
        $maxAge = 31536000,
        $subdomains = false,
        $preload = false
    ) {
        Types::assert(['int|string' => [$maxAge]]);

        $this->hsts['max-age']      = $maxAge;
        $this->hsts['subdomains']   = ($subdomains == true);
        $this->hsts['preload']      = ($preload == true);
    }

    /**
     * Add or remove the `includeSubDomains` flag from the [HSTS](hsts) policy
     * (note this can be done with the {@see hsts} function too).
     *
     * @api
     *
     * @param mixed $mode
     *  Loosely casted to a boolean, `true` adds the `includeSubDomains` flag,
     *  `false` removes it.
     *
     * @return void
     */
    public function hstsSubdomains($mode = true)
    {
        $this->hsts['subdomains'] = ($mode == true);
    }

    /**
     * Add or remove the `preload` flag from the [HSTS](hsts) policy (note this
     * can be done with the {@see hsts} function too).
     *
     * @api
     *
     * @param mixed $mode
     *  Loosely casted to a boolean, `true` adds the `preload` flag, `false`
     *  removes it.
     *
     * @return void
     */
    public function hstsPreload($mode = true)
    {
        $this->hsts['preload'] = ($mode == true);
    }

    # ~~
    # public functions: HPKP

    /**
     * Add and configure the HTTP Public Key Pins header.
     *
     * @param string|array $pins
     *  Either give a valid pin as a string here, or give multiple as an array.
     *  **Note that browsers will not enforce this header unless a backup pin
     *  AND a pin that is currently deployed is specified)**. This means that
     *  at least two pins must be specified. (to do this by passing strings,
     *  simply call {@see hpkp} again with the second pin as the first
     *  argument).
     *
     *  Valid array syntax is as follows
     *  ```php
     *  $pins = array(
     *      array('sha256', 'pin1'),
     *      array('pin2'),
     *      array('pin3', 'sha256')
     *  );
     *  $headers->hpkp($pins);
     *  ```
     *
     *  The above will add `pin1`, `pin2`, and `pin3` with the associated hash
     *  label `sha256`. This is the only valid *  HPKP hashing algorithm at
     *  time of writing.
     *
     * @api
     *
     * @param ?integer|string $maxAge
     *  The length, in seconds that a browser should enforce the policy after
     *  last receiving it.
     *
     *  If this is left unset across all calls to  {@see hpkp}, the value will
     *  default to 10 seconds (which isn't much use – so it is best to set the
     *  value).
     *
     *  Passing `null` indicates that a maxAge should not be modified on this
     *  call (e.g. can be used to prevent overwriting a previous setting).
     *
     * @param ?mixed $subdomains
     *  Loosely casted to a boolean, whether to include the `includeSubDomains`
     *  flag to deploy the policy across the entire domain. `true` enables this
     *  flag.
     *
     *  Passing `null` indicates that a subdomains should not be modified on
     *  this call (e.g. can be used to prevent overwriting a previous setting).
     *
     * @param ?string $reportUri
     *  A reporting address to send violation reports to.
     *
     *  Passing `null` indicates that a reporting address should not be modified
     *  on this call (e.g. can be used to prevent overwriting a previous
     *  setting).
     *
     * @param mixed $reportOnly
     *  Loosely cased to a boolean. If `true`, settings will apply to the
     *  report-only version of this header.
     *
     * @return void
     */
    public function hpkp(
        $pins,
        $maxAge = null,
        $subdomains = null,
        $reportUri = null,
        $reportOnly = null
    ) {
        Types::assert(
            [
                'string|array' => [$pins],
                'int|string' => [$maxAge],
                'string' => [$reportUri]
            ],
            [1, 2, 4]
        );

        $hpkp = &$this->getHPKPObject($reportOnly);

        # set single values

        if (isset($maxAge) or ! isset($this->hpkp['max-age']))
        {
            $hpkp['max-age'] = $maxAge;
        }

        if (isset($subdomains) or ! isset($this->hpkp['includesubdomains']))
        {
            $hpkp['includesubdomains']
                = (isset($subdomains) ? ($subdomains == true) : null);
        }

        if (isset($reportUri) or ! isset($this->hpkp['report-uri']))
        {
            $hpkp['report-uri'] = $reportUri;
        }

        if ( ! is_array($pins))
        {
            $pins = [$pins];
        }

        # set pins

        foreach ($pins as $key => $pin)
        {
            if (is_array($pin) and count($pin) === 2)
            {
                $res = array_intersect($pin, $this->allowedHPKPAlgs);

                if ( ! empty($res))
                {
                    $key = key($res);
                    $hpkp['pins'][] = [
                        $pin[($key + 1) % 2],
                        $pin[$key]
                    ];
                }
                else
                {
                    continue;
                }
            }
            elseif (
                is_string($pin) or (is_array($pin)
                and count($pin) === 1
                and ($pin = $pin[0]) !== false)
            ) {
                $hpkp['pins'][] = [$pin, 'sha256'];
            }
        }
    }

    /**
     * Add and configure the HTTP Public Key Pins header in report-only mode.
     * This is an alias for {@see hpkp} with `$reportOnly` set to `true`.
     *
     * @api
     *
     * @param string|array $pins
     * @param ?integer|string $maxAge
     * @param ?mixed $subdomains
     * @param ?string $reportUri
     *
     * @return void
     */
    public function hpkpro(
        $pins,
        $maxAge = null,
        $subdomains = null,
        $reportUri = null
    ) {
        Types::assert(
            [
                'string|array' => [$pins],
                'int|string' => [$maxAge],
                'string' => [$reportUri]
            ],
            [1, 2, 4]
        );

        return $this->hpkp($pins, $maxAge, $subdomains, $reportUri, true);
    }

    /**
     * Add or remove the `includeSubDomains` flag from the [HPKP](hpkp) policy
     * (note this can be done with the {@see hpkp} function too).
     *
     * @api
     *
     * @param mixed $mode
     *  Loosely casted to a boolean, `true` adds the `includeSubDomains` flag,
     *  `false` removes it.
     * @param mixed $reportOnly
     *  Apply this setting to the report-only version of the HPKP policy header
     *
     * @return void
     */
    public function hpkpSubdomains($mode = true, $reportOnly = null)
    {
        $hpkp = &$this->getHPKPObject($reportOnly);

        $hpkp['includesubdomains'] = ($mode == true);
    }

    /**
     * An alias for {@see hpkpSubdomains} with `$reportOnly` set to `true`
     *
     * @api
     *
     * @param mixed $mode
     *
     * @return void
     */
    public function hpkproSubdomains($mode = true)
    {
        return $this->hpkpSubdomains($mode, true);
    }

    # ~~
    # public functions: general

    /**
     * Calling this function will initiate the following
     *
     * 1. Existing headers from the HttpAdapter's source will be imported into
     *    SecureHeaders' internal list, parsed
     * 2. [Automatic header functions](auto) will be applied
     * 3. [CSP](csp), [HSTS](hsts), and [HPKP](hpkp) policies will be compiled
     *    and added to SecureHeaders' internal header list
     * 4. Headers queued for [removal](removeHeader) will be deleted from
     *    SecureHeaders' internal header list
     * 5. [Safe Mode](safeMode) will examine the list of headers, and make any
     *    required changes according to its settings
     * 6. The HttpAdapter will be instructed to remove all headers from its
     *    header source, Headers will then be copied from SecureHeaders'
     *    internal header list, into the HttpAdapter's (now empty) list of
     *    headers
     * 7. If [error reporting](errorReporting) is enabled (both within
     *    SecureHeaders and according to the PHP configuration values for
     *    error reporting, and whether to display errors)
     *    * Missing security headers will be reported as `E_USER_WARNING`
     *    * Misconfigured headers will be reported as `E_USER_WARNING` or
     *      `E_USER_NOTICE` depending on severity, the former being most
     *      severe an issue.
     *
     *  **Note:** Calling this function is **required** before the first byte
     *  of output in order for SecureHeaders to (be able to) do anything. If
     *  you're not sure when the first byte of output might occur, or simply
     *  don't want to have to call this every time – take a look at
     *  {@see applyOnOutput} to have SecureHeaders take care of this for you.
     *
     * @api
     *
     * @param ?HttpAdapter $http = new GlobalHttpAdapter
     *  An implementation of the {@see HttpAdapter} interface, to which
     *  settings configured via SecureHeaders will be applied.
     *
     * @return HeaderBag
     *  Returns the headers
     */
    public function apply(HttpAdapter $http = null)
    {
        # For ease of use, we allow calling this method without an adapter,
        # which will cause the headers to be sent with PHP's global methods.
        if (is_null($http))
        {
            $http = new GlobalHttpAdapter();
        }

        $headers = $http->getHeaders();

        foreach ($this->pipeline() as $operation)
        {
            $operation->modify($headers);

            if ($operation instanceof ExposesErrors)
            {
                $this->errors = array_merge(
                    $this->errors,
                    $operation->collectErrors()
                );
            }
        }

        $http->sendHeaders($headers);

        $this->reportMissingHeaders($headers);
        $this->validateHeaders($headers);
        $this->reportErrors();

        return $headers;
    }

    /**
     * Return an array of header operations, depending on current configuration.
     *
     * These can then be applied to e.g. the current set of headers.
     *
     * @api
     *
     * @return Operation[]
     */
    private function pipeline()
    {
        $operations = [];

        if ($this->strictMode)
        {
            $operations[] = new AddHeader(
                'Strict-Transport-Security',
                'max-age=31536000; includeSubDomains; preload'
            );

            $operations[] = new AddHeader(
                'Expect-CT',
                'max-age=31536000; enforce'
            );
        }

        # Apply security headers for all (HTTP and HTTPS) connections
        if ($this->automatic(self::AUTO_ADD))
        {
            foreach ($this->headerProposals as $header => $value)
            {
                $operations[] = new AddHeader($header, $value);
            }
        }

        if ($this->automatic(self::AUTO_REMOVE))
        {
            $operations[] = new RemoveHeaders(
                ['Server', 'X-Powered-By']
            );
        }

        # Add a secure flag to cookies that look like they hold session data
        if ($this->automatic(self::AUTO_COOKIE_SECURE))
        {
            $operations[] = ModifyCookies::matchingPartially(
                $this->protectedCookies['substrings'],
                'Secure'
            );
            $operations[] = ModifyCookies::matchingFully(
                $this->protectedCookies['names'],
                'Secure'
            );
        }

        # Add a httpOnly flag to cookies that look like they hold session data
        if ($this->automatic(self::AUTO_COOKIE_HTTPONLY))
        {
            $operations[] = ModifyCookies::matchingPartially(
                $this->protectedCookies['substrings'],
                'HttpOnly'
            );
            $operations[] = ModifyCookies::matchingFully(
                $this->protectedCookies['names'],
                'HttpOnly'
            );
        }

        if (
            ($this->automaticHeaders & self::AUTO_COOKIE_SAMESITE)
            === self::AUTO_COOKIE_SAMESITE
        ) {
            # add SameSite to cookies that look like they hold
            # session data

            $sameSite = $this->injectableSameSiteValue();

            $operations[] = ModifyCookies::matchingPartially(
                $this->protectedCookies['substrings'],
                'SameSite',
                $sameSite
            );
            $operations[] = ModifyCookies::matchingFully(
                $this->protectedCookies['names'],
                'SameSite',
                $sameSite
            );
        }

        $operations[] = new CompileCSP(
            $this->csp,
            $this->cspro,
            $this->csproBlacklist,
            $this->cspLegacy
        );

        if ( ! empty($this->hsts))
        {
            $operations[] = new CompileHSTS($this->hsts);
        }

        if ( ! empty($this->expectCT))
        {
            $operations[] = new CompileExpectCT($this->expectCT);
        }

        $operations[] = new CompileHPKP($this->hpkp, $this->hpkpro);

        $operations[] = new RemoveCookies(array_keys($this->removedCookies));

        # Remove all headers that were configured to be removed
        $operations[] = new RemoveHeaders(array_keys($this->removedHeaders));

        if ($this->strictMode)
        {
            $operations[] = new InjectStrictDynamic($this->allowedCSPHashAlgs);
        }

        if ($this->safeMode)
        {
            $operations[] = new ApplySafeMode($this->safeModeExceptions);
        }

        return $operations;
    }

    # ~~
    # public functions: non-user
    #
    # These aren't documented because they aren't meant to be used directly,
    # but still need to have public visability.
    #
    # This function is NOT part of the public API guarenteed by symver

    /**
     * @ignore
     *
     * Method given to `ob_start` when using {@see applyOnOutput)
     *
     * @param string $buffer
     * @return string
     */
    public function returnBuffer($buffer = null)
    {
        if ($this->isBufferReturned)
        {
            return $buffer;
        }

        $this->apply($this->applyOnOutput);

        if (ob_get_level() and ! empty($this->errorString))
        {
            # prepend any errors to the buffer string (any errors that were
            # echoed will have been lost during an ob_start callback)
            $buffer = $this->errorString . $buffer;
        }

        # if we were called as part of ob_start, make note of this
        # (avoid doing redundent work if called again)
        $this->isBufferReturned = true;

        return $buffer;
    }

    # ~~
    # Private Functions

    # ~~
    # private functions: validation

    /**
     * Validate headers in the HeaderBag and store any errors internally.
     *
     * @param HeaderBag $headers
     * @return void
     */
    private function validateHeaders(HeaderBag $headers)
    {
        $this->errors = array_merge(
            $this->errors,
            Validator::validate($headers)
        );
    }

    # ~~
    # private functions: Content-Security-Policy (CSP)

    # Content-Security-Policy: Policy string additions

    /**
     * Add a CSP friendly source $friendlySource to a CSP directive
     * $friendlyDirective in either enforcement or report only mode.
     *
     * @param string $friendlyDirective
     * @param string $friendlySource
     * @param bool $reportOnly
     * @return void
     */
    private function cspAllow(
        $friendlyDirective,
        $friendlySource = null,
        $reportOnly = null
    ) {
        Types::assert(
            ['string' => [$friendlyDirective, $friendlySource]]
        );

        $directive = $this->longDirective($friendlyDirective);

        $source = $this->longSource($friendlySource);

        $this->addCSPSource($directive, $source, $reportOnly);
    }

    /**
     * Takes friendly directive $friendlyDirective and returns the
     * corresponding long (proper) directive.
     *
     * @param string $friendlyDirective
     * @return string
     */
    private function longDirective($friendlyDirective)
    {
        Types::assert(['string' => [$friendlyDirective]]);

        $friendlyDirective = strtolower($friendlyDirective);

        if (isset($this->cspDirectiveShortcuts[$friendlyDirective]))
        {
            $directive = $this->cspDirectiveShortcuts[$friendlyDirective];
        }
        else
        {
            $directive = $friendlyDirective;
        }

        return $directive;
    }

    /**
     * Takes friendly source $friendlySource and returns the
     * corresponding long (proper) source.
     *
     * @param string $friendlySource
     * @return string
     */
    private function longSource($friendlySource)
    {
        Types::assert(['string' => [$friendlySource]]);

        $lowerFriendlySource = strtolower($friendlySource);

        if (isset($this->cspSourceShortcuts[$lowerFriendlySource]))
        {
            $source = $this->cspSourceShortcuts[$lowerFriendlySource];
        }
        else
        {
            $source = $friendlySource;
        }

        return $source;
    }

    /**
     * Add a CSP source $source to a CSP directive $directive in either
     * enforcement or report only mode. Both $directive and $source must be
     * long (defined in CSP spec).
     *
     * Will return false on error, true on success.
     *
     * @param string $directive
     * @param string $source
     * @param bool $reportOnly
     * @return bool
     */
    private function addCSPSource(
        $directive,
        $source = null,
        $reportOnly = null
    ) {
        Types::assert(['string' => [$directive, $source]]);

        $csp = &$this->getCSPObject($reportOnly);

        if ( ! isset($csp[$directive]))
        {
            $this->addCSPDirective(
                $directive,
                ! isset($source),
                $reportOnly
            );
        }

        if ($csp[$directive] === null)
        {
            return false;
        }

        if (isset($source))
        {
            $source = str_replace(';', '', $source);

            $csp[$directive][strtolower($source)] = $source;
        }

        return true;
    }

    # Content-Security-Policy: Policy as array

    /**
     * Add a CSP array $csp of friendly sources to corresponding
     * firendly directives in either enforcement or report only mode.
     *
     * @param array $csp
     * @param bool $reportOnly
     * @return void
     */
    private function cspArray(array $csp, $reportOnly = false)
    {
        foreach ($csp as $friendlyDirective => $sources)
        {
            if (is_array($sources) and ! empty($sources))
            {
                foreach ($sources as $friendlySource)
                {
                    $this->cspAllow(
                        $friendlyDirective,
                        $friendlySource,
                        $reportOnly
                    );
                }
            }
            elseif (is_int($friendlyDirective) and is_string($sources))
            {
                # special case that $sources is actually a directive name,
                # with an int index
                $friendlyDirective = $sources;

                # we'll treat this case as a CSP flag
                $this->cspAllow($friendlyDirective, null, $reportOnly);
            }
            elseif ( ! is_array($sources))
            {
                # special case that $sources isn't an array (possibly a string
                # source, or null
                $this->cspAllow($friendlyDirective, $sources, $reportOnly);
            }
        }
    }

    /**
     * Retrieve a reference to either the CSP enforcement, or CSP report only
     * array.
     *
     * @param bool $reportOnly
     * @return &array
     */
    private function &getCSPObject($reportOnly)
    {
        if ( ! isset($reportOnly) or ! $reportOnly)
        {
            $csp = &$this->csp;
        }
        else
        {
            $csp = &$this->cspro;
        }

        return $csp;
    }

    /**
     * Add a CSP directive $directive in either enforcement or report only mode.
     * $directive must be long (defined in CSP spec). Set $isFlag to true if
     * adding a directive that should not hold source values.
     *
     * Will return false on error, true on success.
     *
     * @param string $directive
     * @param bool $isFlag
     * @param bool $reportOnly
     * @return bool
     */
    private function addCSPDirective(
        $directive,
        $isFlag = null,
        $reportOnly = null
    ) {
        Types::assert(['string' => [$directive]]);

        if ( ! isset($isFlag))
        {
            $isFlag = false;
        }

        $csp = &$this->getCSPObject($reportOnly);

        if (isset($csp[$directive]))
        {
            return false;
        }

        if ( ! $isFlag)
        {
            $csp[$directive] = [];
        }
        else
        {
            $csp[$directive] = null;
        }

        return true;
    }

    /**
     * Generate a hash with algorithm $algo for insertion in a CSP either of
     * $string, or of the contents of a file at path $string iff $isFile is
     * truthy.
     *
     * @param string $string
     * @param string $algo
     * @param bool $isFile
     * @return string
     */
    private function cspDoHash(
        $string,
        $algo = null,
        $isFile = null
    ) {
        Types::assert(['string' => [$string, $algo]]);

        if ( ! isset($algo))
        {
            $algo = 'sha256';
        }

        if ( ! isset($isFile))
        {
            $isFile = false;
        }

        if ( ! $isFile)
        {
            $hash = hash($algo, $string, true);
        }
        else
        {
            if (file_exists($string))
            {
                $hash = hash_file($algo, $string, true);
            }
            else
            {
                $this->addError(
                    __FUNCTION__.': The specified file '
                    . "<strong>'$string'</strong>, does not exist"
                );

                return '';
            }
        }

        return base64_encode($hash);
    }

    /**
     * Generate a nonce for insertion in a CSP.
     *
     * @return string
     */
    private function cspGenerateNonce()
    {
        $nonce = base64_encode(
            openssl_random_pseudo_bytes(30, $isCryptoStrong)
        );

        if ( ! $isCryptoStrong)
        {
            $this->addError(
                'OpenSSL (openssl_random_pseudo_bytes) reported that it did
                <strong>not</strong> use a cryptographically strong algorithm
                to generate the nonce for CSP.',

                E_USER_WARNING
            );
        }

        return $nonce;
    }

    # ~~
    # private functions: HPKP

    /**
     * Retrieve a reference to either the HPKP enforcement, or HPKP report only
     * array.
     *
     * @param bool $reportOnly
     * @return &array
     */
    private function &getHPKPObject($reportOnly)
    {
        if ( ! isset($reportOnly) or ! $reportOnly)
        {
            $hpkp = &$this->hpkp;
        }
        else
        {
            $hpkp = &$this->hpkpro;
        }

        return $hpkp;
    }

    # ~~
    # private functions: general

    /**
     * Add and store an error internally.
     *
     * @param string $message
     * @param int $level
     * @return void
     */
    private function addError($message, $level = E_USER_NOTICE)
    {
        Types::assert(
            ['string' => [$message], 'int' => [$level]]
        );

        $this->errors[] = new Error($message, $level);
    }

    /**
     * Use PHPs `trigger_error` function to trigger all internally stored
     * errors if error reporting is enabled for $this. The error handler will
     * be temporarily set to {@see errorHandler} while errors are dispatched via
     * `trigger_error`.
     *
     * @return void
     */
    private function reportErrors()
    {
        if ( ! $this->errorReporting)
        {
            return;
        }

        set_error_handler([get_class(), 'errorHandler']);

        if ( ! empty($this->errors))
        {
            $this->isBufferReturned = true;
        }

        foreach ($this->errors as $error)
        {
            trigger_error($error->getMessage(), $error->getLevel());
        }

        restore_error_handler();
    }

    /**
     * Determine the appropriate sameSite value to inject.
     *
     * @return string
     */
    private function injectableSameSiteValue()
    {
        if ( ! isset($this->sameSiteCookies) and $this->strictMode)
        {
            $sameSite = 'Strict';
        }
        elseif ( ! isset($this->sameSiteCookies))
        {
            $sameSite = 'Lax';
        }
        else
        {
            $sameSite = $this->sameSiteCookies;
        }

        return $sameSite;
    }

    /**
     * Echo an error iff PHPs settings allow error reporting, at the level of
     * errors given, and PHPs display_errors setting is on. Will return `true`
     * if an error is echoed, `false` otherwise.
     *
     * @param int $level
     * @param string $message
     * @return bool
     */
    private function errorHandler($level, $message)
    {
        Types::assert(
            ['int' => [$level], 'string' => [$message]]
        );

        if (error_reporting() & $level
            and (strtolower(ini_get('display_errors')) === 'on'
            and ini_get('display_errors'))
        ) {
            if ($level === E_USER_NOTICE)
            {
                $error = '<strong>Notice:</strong> ' .$message. "<br><br>\n\n";
            }
            elseif ($level === E_USER_WARNING)
            {
                $error = '<strong>Warning:</strong> ' .$message. "<br><br>\n\n";
            }

            if (isset($error))
            {
                echo $error;
                $this->errorString .= $error;
                return true;
            }
        }
        return false;
    }

    /**
     * If $headers is missing certain headers of security value that are not on
     * the user-defined exception to reporting list then internally store an
     * error warning that the header is not present.
     *
     * @param HeaderBag $headers
     * @return void
     */
    private function reportMissingHeaders(HeaderBag $headers)
    {
        foreach ($this->reportMissingHeaders as $header)
        {
            if (
                ! $headers->has($header)
                and empty($this->reportMissingExceptions[strtolower($header)])
            ) {
                $this->addError(
                    "Missing security header: '$header'",
                    E_USER_WARNING
                );
            }
        }
    }

    /**
     * Determine whether the given $operation may be executed based on the
     * user-controllable automatic settings.
     *
     * @param int $operation
     * @return bool
     */
    private function automatic($operation)
    {
        return ($this->automaticHeaders & $operation) === $operation;
    }
}
