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
# Copyright (c) 2016 Aidan Woods
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
use Aidantwoods\SecureHeaders\Operations\CompileHPKP;
use Aidantwoods\SecureHeaders\Operations\CompileHSTS;
use Aidantwoods\SecureHeaders\Operations\InjectStrictDynamic;
use Aidantwoods\SecureHeaders\Operations\ModifyCookies;
use Aidantwoods\SecureHeaders\Operations\RemoveHeaders;
use Aidantwoods\SecureHeaders\Util\Types;

class SecureHeaders{

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
    protected $safeModeExceptions       = array();

    protected $automaticHeaders         = self::AUTO_ALL;

    protected $sameSiteCookies          = null;

    protected $correctHeaderName        = true;

    protected $reportMissingExceptions  = array();

    protected $protectedCookies         = array(
        'substrings'    => array(
            'sess',
            'auth',
            'login',
            'csrf',
            'xsrf',
            'token',
            'antiforgery'
        ),
        'names'         => array(
            'sid',
            's',
            'persistent'
        )
    );

    protected $headerProposals          = array(
        'X-Permitted-Cross-Domain-Policies' => 'none',
        'X-XSS-Protection'                  => '1; mode=block',
        'X-Content-Type-Options'            => 'nosniff',
        'X-Frame-Options'                   => 'Deny'
    );

    # ~~
    # private variables: (non settings)

    private $removedHeaders     = array();

    private $cookies            = array();
    private $removedCookies     = array();

    private $errors             = array();
    private $errorString;

    private $csp                = array();
    private $cspro              = array();

    private $cspNonces          = array(
        'enforced'      =>  array(),
        'reportOnly'    =>  array()
    );

    private $hsts               = array();

    private $hpkp               = array();
    private $hpkpro             = array();

    private $isBufferReturned   = false;

    private $doneOnOutput       = false;

    # private variables: (pre-defined static structures)

    private $cspDirectiveShortcuts  = array(
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
    );

    private $cspSourceShortcuts     = array(
        'self'              =>  "'self'",
        'none'              =>  "'none'",
        'unsafe-inline'     =>  "'unsafe-inline'",
        'unsafe-eval'       =>  "'unsafe-eval'",
        'strict-dynamic'    =>  "'strict-dynamic'"
    );

    private $cspSensitiveDirectives = array(
        'default-src',
        'script-src',
        'style-src',
        'object-src'
    );

    protected $csproBlacklist       = array(
        'block-all-mixed-content',
        'upgrade-insecure-requests'
    );

    private $allowedCSPHashAlgs     = array(
        'sha256',
        'sha384',
        'sha512'
    );

    private $allowedHPKPAlgs        = array(
        'sha256'
    );

    private $reportMissingHeaders   = array(
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Permitted-Cross-Domain-Policies',
        'X-XSS-Protection',
        'X-Content-Type-Options',
        'X-Frame-Options'
    );

    private $cspSourceWildcardRe
        =   '/(?:[ ]|^)\K
            (?:
            # catch open protocol wildcards
                [^:.\/ ]+?
                [:]
                (?:[\/]{2})?
                [*]?
            |
            # catch domain based wildcards
                (?: # optional protocol
                    [^:. ]+?
                    [:]
                    [\/]{2}
                )?
                # optionally match domain text before *
                [^\/:* ]*?
                [*]
                (?: # optionally match TLDs after *
                    (?:[^. ]*?[.])?
                    (?:[^. ]{1,3}[.])?
                    [^. ]*
                )?
            )
            # assert that match covers the entire value
            (?=[ ;]|$)/ix';

    # ~
    # Constants

    # auto-headers

    const AUTO_ADD              =  1; # 0b00001
    const AUTO_REMOVE           =  2; # 0b00010
    const AUTO_COOKIE_SECURE    =  4; # 0b00100
    const AUTO_COOKIE_HTTPONLY  =  8; # 0b01000
    const AUTO_COOKIE_SAMESITE  = 16; # 0b10000
    const AUTO_ALL              = 31; # 0b11111

    # cookie upgrades

    const COOKIE_NAME           =  1; # 0b00001
    const COOKIE_SUBSTR         =  2; # 0b00010
    const COOKIE_ALL            =  3; # COOKIE_NAME | COOKIE_SUBSTR
    const COOKIE_REMOVE         =  4; # 0b00100
    const COOKIE_DEFAULT        =  2; # ~COOKIE_REMOVE & COOKIE_SUBSTR

    # ~~
    # Public Functions

    public function doneOnOutput($mode = true)
    {
        if ($mode == true and $this->doneOnOutput === false)
        {
            ob_start(array($this, 'returnBuffer'));

            $this->doneOnOutput = true;
        }
        elseif ($this->doneOnOutput === true)
        {
            ob_end_clean();

            $this->doneOnOutput = false;
        }
    }

    # ~~
    # public functions: settings

    # ~~
    # Settings: Safe Mode

    # safe-mode enforces settings that shouldn't cause too much accidental
    # down-time safe-mode intentionally overwrites user specified settings

    public function safeMode($mode = true)
    {
        $this->safeMode = ($mode == true and strtolower($mode) !== 'off');
    }

    # if operating in safe mode, use this to manually allow a specific header

    public function safeModeException($name)
    {
        Types::assert(array('string' => array($name)));

        $this->safeModeExceptions[strtolower($name)] = true;
    }

    # ~~
    # Settings: Strict Mode

    public function strictMode($mode = true)
    {
        $this->strictMode = ($mode == true and strtolower($mode) !== 'off');
    }

    # ~~
    # Settings: Error Reporting

    public function errorReporting($mode)
    {
        $this->errorReporting = ($mode == true);
    }

    # use this to manually disable missing reports on a specific header

    public function reportMissingException($name)
    {
        Types::assert(array('string' => array($name)));

        $this->reportMissingExceptions[strtolower($name)] = true;
    }

    # ~~
    # Settings: Automatic Behaviour

    public function auto($mode = self::AUTO_ALL)
    {
        Types::assert(array('int' => array($mode)));

        $this->automaticHeaders = $mode;
    }

    # ~~
    # Settings: Headers

    public function correctHeaderName($mode = true)
    {
        $this->correctHeaderName = (true == $mode);
    }

    # ~~
    # Settings: Nonces

    public function returnExistingNonce($mode = true)
    {
        $this->returnExistingNonce = ($mode == true);
    }

    # ~~
    # Settings: Cookies

    public function sameSiteCookies($mode = null)
    {
        Types::assert(array('string' => array($mode)));

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

    public function removeHeader($name)
    {
        Types::assert(array('string' => array($name)));

        $name = strtolower($name);
        $this->removedHeaders[$name] = true;
    }

    # ~~
    # public functions: cookies

    public function protectedCookie(
        $name,
        $mode = self::COOKIE_DEFAULT
    ) {
        Types::assert(
            array(
                'string|array' => array($name),
                'int' => array($mode)
            )
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

        $stringTypes = array();

        if (($mode & self::COOKIE_NAME) === self::COOKIE_NAME)
            $stringTypes[] = 'names';

        if (($mode & self::COOKIE_SUBSTR) === self::COOKIE_SUBSTR)
            $stringTypes[] = 'substrings';

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

    public function removeCookie($name)
    {
        Types::assert(array('string' => array($name)));

        unset($this->cookies[$name]);

        $this->removedCookies[strtolower($name)] = true;
    }

    # ~~
    # public functions: Content-Security-Policy (CSP)

    public function csp()
    {
        $args = func_get_args();
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
        if ( ! isset($reportOnly)) $reportOnly = false;

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

    public function cspro()
    {
        $args = func_get_args();

        foreach ($args as $i => $arg)
        {
            if (is_bool($arg) or is_int($arg))
            {
                unset($args[$i]);
            }
        }

        $args = array_values($args);

        array_unshift($args, true);

        call_user_func_array(array($this, 'csp'), $args);
    }

     # Content-Security-Policy: Settings

    public function cspLegacy($mode = true)
    {
        $this->cspLegacy = ($mode == true);
    }

    # Content-Security-Policy: Policy string removals

    public function removeCSPSource($directive, $source, $reportOnly = null)
    {
        Types::assert(array('string' => array($directive, $source)));

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

    public function removeCSPDirective($directive, $reportOnly = null)
    {
        Types::assert(array('string' => array($directive)));

        $csp = &$this->getCSPObject($reportOnly);

        $directive = strtolower($directive);

        if ( ! isset($csp[$directive]))
        {
            return false;
        }

        unset($csp[$directive]);

        return true;
    }

    public function resetCSP($reportOnly = null)
    {
        $csp = &$this->getCSPObject($reportOnly);

        $csp = array();
    }

    # Content-Security-Policy: Hashing

    public function cspHash(
        $friendlyDirective,
        $string,
        $algo = null,
        $isFile = null,
        $reportOnly = null
    ) {
        Types::assert(
            array('string' => array($friendlyDirective, $string, $algo))
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

    public function csproHash(
        $friendlyDirective,
        $string,
        $algo = null,
        $isFile = null
    ) {
        Types::assert(
            array('string' => array($friendlyDirective, $string, $algo))
        );

        return $this->cspHash(
            $friendlyDirective,
            $string,
            $algo,
            $isFile,
            true
        );
    }

    public function cspHashFile(
        $friendlyDirective,
        $string,
        $algo = null,
        $reportOnly = null
    ) {
        Types::assert(
            array('string' => array($friendlyDirective, $string, $algo))
        );

        return $this->cspHash(
            $friendlyDirective,
            $string,
            $algo,
            true,
            $reportOnly
        );
    }

    public function csproHashFile($friendlyDirective, $string, $algo = null)
    {
        Types::assert(
            array('string' => array($friendlyDirective, $string, $algo))
        );

        return $this->cspHash($friendlyDirective, $string, $algo, true, true);
    }

    # Content-Security-Policy: Nonce

    public function cspNonce($friendlyDirective, $reportOnly = null)
    {
        Types::assert(array('string' => array($friendlyDirective)));

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

    public function csproNonce($friendlyDirective)
    {
        Types::assert(array('string' => array($friendlyDirective)));

        return $this->cspNonce($friendlyDirective, true);
    }

    # ~~
    # public functions: HSTS

    public function hsts(
        $maxAge = 31536000,
        $subdomains = false,
        $preload = false
    ) {
        Types::assert(array('int|string' => array($maxAge)));

        $this->hsts['max-age']      = $maxAge;
        $this->hsts['subdomains']   = ($subdomains == true);
        $this->hsts['preload']      = ($preload == true);
    }

    public function hstsSubdomains($mode = true)
    {
        $this->hsts['subdomains'] = ($mode == true);
    }

    public function hstsPreload($mode = true)
    {
        $this->hsts['preload'] = ($mode == true);
    }

    # ~~
    # public functions: HPKP

    public function hpkp(
        $pins,
        $maxAge = null,
        $subdomains = null,
        $reportUri = null,
        $reportOnly = null
    ) {
        Types::assert(
            array(
                'string|array' => array($pins),
                'int|string' => array($maxAge),
                'string' => array($reportUri)
            ),
            array(1, 2, 4)
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

        if ( ! is_array($pins)) $pins = array($pins);

        # set pins

        foreach ($pins as $key => $pin)
        {
            if (is_array($pin) and count($pin) === 2)
            {
                $res = array_intersect($pin, $this->allowedHPKPAlgs);

                if ( ! empty($res))
                {
                    $key = key($res);
                    $hpkp['pins'][] = array(
                        $pin[($key + 1) % 2],
                        $pin[$key]
                    );
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
                $hpkp['pins'][] = array($pin, 'sha256');
            }
        }
    }

    public function hpkpro(
        $pins,
        $maxAge = null,
        $subdomains = null,
        $reportUri = null
    ) {
        Types::assert(
            array(
                'string|array' => array($pins),
                'int|string' => array($maxAge),
                'string' => array($reportUri)
            ),
            array(1, 2, 4)
        );

        return $this->hpkp($pins, $maxAge, $subdomains, $reportUri, true);
    }

    public function hpkpSubdomains($mode = true, $reportOnly = null)
    {
        $hpkp = &$this->getHPKPObject($reportOnly);

        $hpkp['includesubdomains'] = ($mode == true);
    }

    public function hpkproSubdomains($mode = true)
    {
        return $this->hpkpSubdomains($mode, true);
    }

    # ~~
    # public functions: general

    public function done()
    {
        return $this->apply();
    }

    public function apply(HttpAdapter $http = null)
    {
        // For ease of use, we allow calling this method without an adapter,
        // which will cause the headers to be sent with PHP's global methods.
        if (is_null($http))
        {
            $http = new GlobalHttpAdapter();
        }

        $headers = $http->getHeaders();

        foreach ($this->pipeline() as $operation)
        {
            $operation->modify($headers);
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
     * @return Operation[]
     */
    private function pipeline()
    {
        $operations = array();

        if ($this->strictMode)
        {
            $operations[] = new AddHeader(
                'Strict-Transport-Security',
                'max-age=31536000; includeSubDomains; preload'
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
                array('Server', 'X-Powered-By')
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

        $operations[] = new CompileHPKP($this->hpkp, $this->hpkpro);

        # Remove all headers that were configured to be removed
        $operations[] = new RemoveHeaders(array_keys($this->removedHeaders));

        if ($this->safeMode)
        {
            $operations[] = new ApplySafeMode($this->safeModeExceptions);
        }

        if ($this->strictMode)
        {
            $operations[] = new InjectStrictDynamic($this->allowedCSPHashAlgs);
        }

        return $operations;
    }

    # ~~
    # public functions: non-user
    #
    # These aren't documented because they aren't meant to be used directly,
    # but still need to have public visability.

    public function returnBuffer($buffer = null)
    {
        if ($this->isBufferReturned) return $buffer;

        $this->done();

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

    private function validateHeaders(HeaderBag $headers)
    {
        $headers->forEachNamed(
            'content-security-policy',
            function (Header $header)
            {
                $this->validateSrcAttribute($header, 'default-src');
                $this->validateSrcAttribute($header, 'script-src');

                $this->validateCSPAttributes($header);
            }
        );

        $headers->forEachNamed(
            'content-security-policy-report-only',
            function (Header $header)
            {
                if (
                    ! $header->hasAttribute('report-uri')
                    or  ! preg_match(
                        '/https:\/\/[a-z0-9\-]+[.][a-z]{2,}.*/i',
                        $header->getAttributeValue('report-uri')
                    )
                ) {
                    $friendlyHeader = $header->getFriendlyName();

                    $this->addError($friendlyHeader.' header was sent,
                        but an invalid, or no reporting address was given.
                        This header will not enforce violations, and with no
                        reporting address specified, the browser can only
                        report them locally in its console. Consider adding
                        a reporting address to make full use of this header.'
                    );
                }

                $this->validateSrcAttribute($header, 'default-src');
                $this->validateSrcAttribute($header, 'script-src');

                $this->validateCSPAttributes($header);
            }
        );
    }

    # ~~
    # private functions: Content-Security-Policy (CSP)

    # Content-Security-Policy: Policy string additions

    private function cspAllow(
        $friendlyDirective,
        $friendlySource = null,
        $reportOnly = null
    ) {
        Types::assert(
            array('string' => array($friendlyDirective, $friendlySource))
        );

        $directive = $this->longDirective($friendlyDirective);

        $source = $this->longSource($friendlySource);

        $this->addCSPSource($directive, $source, $reportOnly);
    }

    private function longDirective($friendlyDirective)
    {
        # takes directive A and returns the corresponding long directive, if the
        # directive A is friendly directive. Otherwise, directive A will be
        # returned

        Types::assert(array('string' => array($friendlyDirective)));

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

    private function longSource($friendlySource)
    {
        # takes source A and returns the corresponding long source, if the
        # source A is friendly source. Otherwise, source A will be returned

        Types::assert(array('string' => array($friendlySource)));

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

    private function addCSPSource(
        $directive,
        $source = null,
        $reportOnly = null
    ) {
        Types::assert(array('string' => array($directive, $source)));

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

    private function addCSPDirective(
        $directive,
        $isFlag = null,
        $reportOnly = null
    ) {
        Types::assert(array('string' => array($directive)));

        if ( ! isset($isFlag)) $isFlag = false;

        $csp = &$this->getCSPObject($reportOnly);

        if (isset($csp[$directive]))
        {
            return false;
        }

        if ( ! $isFlag) $csp[$directive] = array();
        else $csp[$directive] = null;

        return true;
    }

    private function cspDoHash(
        $string,
        $algo = null,
        $isFile = null
    ) {
        Types::assert(array('string' => array($string, $algo)));

        if ( ! isset($algo)) $algo = 'sha256';

        if ( ! isset($isFile)) $isFile = false;

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

    private function addError($message, $error = E_USER_NOTICE)
    {
        Types::assert(
            array('string' => array($message), 'int' => array($error))
        );

        $message = preg_replace('/[\\\]\n\s*/', '', $message);

        $message = preg_replace('/\s+/', ' ', $message);

        $this->errors[] = array($message, $error);
    }

    private function reportErrors()
    {
        if ( ! $this->errorReporting) return;

        set_error_handler(array(get_class(), 'errorHandler'));

        if ( ! empty($this->errors)) $this->isBufferReturned = true;

        foreach ($this->errors as $msgLevel)
        {
            list($message, $level) = $msgLevel;

            trigger_error($message, $level);
        }

        restore_error_handler();
    }

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

    private function errorHandler($level, $message)
    {
        Types::assert(
            array('int' => array($level), 'string' => array($message))
        );

        if (    error_reporting() & $level
            and (strtolower(ini_get('display_errors')) === 'on'
            and ini_get('display_errors'))
        ){
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
     * @return bool
     */
    private function automatic($operation)
    {
        return ($this->automaticHeaders & $operation) === $operation;
    }

    private function validateSrcAttribute(Header $header, $attributeName)
    {
        if ($header->hasAttribute($attributeName))
        {
            $value = $header->getAttributeValue($attributeName);

            $badFlags = array("'unsafe-inline'", "'unsafe-eval'");
            foreach ($badFlags as $badFlag)
            {
                if (strpos($value, $badFlag) !== false)
                {
                    $friendlyHeader = $header->getFriendlyName();

                    $this->addError(
                        $friendlyHeader . ' contains the <b>'
                        . $badFlag . '</b> keyword in <b>' . $attributeName
                        . '</b>, which prevents CSP protecting
                                against the injection of arbitrary code
                                into the page.',

                        E_USER_WARNING
                    );
                }
            }
        }
    }

    private function validateCSPAttributes(Header $header)
    {
        $header->forEachAttribute(
            function ($name, $value) use ($header)
            {
                if (preg_match_all($this->cspSourceWildcardRe, $value, $matches))
                {
                    if ( ! in_array($name, $this->cspSensitiveDirectives))
                    {
                        # if we're not looking at one of the above, we'll
                        # be a little less strict with data:
                        if (($key = array_search('data:', $matches[0])) !== false)
                        {
                            unset($matches[0][$key]);
                        }
                    }

                    if ( ! empty($matches[0]))
                    {
                        $friendlyHeader = $header->getFriendlyName();

                        $this->addError(
                            $friendlyHeader . ' ' . (count($matches[0]) > 1 ?
                                'contains the following wildcards '
                                : 'contains a wildcard ')
                            . '<b>' . implode(', ', $matches[0]) . '</b> as a
                                source value in <b>' . $name . '</b>; this can
                                allow anyone to insert elements covered by
                                the <b>' . $name . '</b> directive into the
                                page.',

                            E_USER_WARNING
                        );
                    }
                }

                if (preg_match_all('/(?:[ ]|^)\Khttp[:][^ ]*/', $value, $matches))
                {
                    $friendlyHeader = $header->getFriendlyName();

                    $this->addError(
                        $friendlyHeader . ' contains the insecure protocol
                            HTTP in ' . (count($matches[0]) > 1 ?
                            'the following source values '
                            : 'a source value ')
                        . '<b>' . implode(', ', $matches[0]) . '</b>; this can
                            allow anyone to insert elements covered by the
                            <b>' . $name . '</b> directive into the page.',

                        E_USER_WARNING
                    );
                }
            }
        );
    }
}
