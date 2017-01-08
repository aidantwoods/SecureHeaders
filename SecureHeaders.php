<?php
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

class SecureHeaders{

    # ~~
    # Version

    const version = '1.0.0';

    # ~~
    # protected variables: settings

    protected $errorReporting = true;

    protected $cspLegacy = false;
    protected $returnExistingNonce = true;

    protected $strictMode = false;

    protected $safeMode = false;
    protected $safeModeExceptions = array();

    protected $automaticHeaders = self::AUTO_ALL;

    protected $correctHeaderName = true;

    protected $protectedCookies = array(
        'substrings' => array(
            'sess',
            'auth',
            'login',
            'csrf',
            'xsrf',
            'token',
            'antiforgery'
        ),
        'names' => array(
            'sid',
            's',
            'persistent'
        )
    );

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

    # safe-mode enforces settings that shouldn't cause too much accidental
    # down-time safe-mode intentionally overwrites user specified settings

    public function safeMode($mode = true)
    {
        if ($mode == false or strtolower($mode) === 'off')
        {
            $this->safeMode = false;
        }
        else
        {
            $this->safeMode = true;
        }
    }

    # if operating in safe mode, use this to manually allow a specific header

    public function safeModeException($name)
    {
        $this->assertTypes(array('string' => array($name)));

        $this->safeModeExceptions[strtolower($name)] = true;
    }

    public function strictMode($mode = true)
    {
        if ($mode == false or strtolower($mode) === 'off')
        {
            $this->strictMode = false;
        }
        else
        {
            $this->strictMode = true;
        }
    }

    public function returnExistingNonce($mode = true)
    {
        $this->returnExistingNonce = ($mode == true);
    }

    public function auto($mode = self::AUTO_ALL)
    {
        $this->assertTypes(array('int' => array($mode)));

        $this->automaticHeaders = $mode;
    }

    public function correctHeaderName($mode = true)
    {
        $this->correctHeaderName = (true == $mode);
    }

    public function protectedCookie(
        $name,
        $mode = self::COOKIE_DEFAULT
    ) {
        $this->assertTypes(
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

        if (($mode & self::COOKIENAME) === self::COOKIENAME)
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

    # ~~
    # public functions: raw headers

    public function addHeader(
        $name,
        $value = null
    ) {
        $this->assertTypes(array('string' => array($name, $value)));

        if (
            $this->correctHeaderName
            and preg_match('/([^:]+)/', $name, $match)
        ) {
            $name = $match[1];

            $capitalisedName = preg_replace_callback(
                '/(?<=[-\s]|^)[^-\s]/',
                function ($match){
                    return strtoupper($match[0]);
                },
                $name
            );
        }
        else
        {
            $capitalisedName = $name;
        }

        $name = strtolower($name);

        if (
            $this->proposeHeaders
            and (
                isset($this->removedHeaders[$name])
                or isset($this->headers[$name])
            )
        ) {
            # a proposal header will only be added if the intented header:
            # {has not been staged for removal} or {already added}
            return;
        }

        # if its actually a cookie, this requires special handling
        if ($name === 'set-cookie')
        {
            $this->addCookie($value, null, true);
        }
        # a few headers are better handled as an imported policy
        elseif (
            $this->allowImports
            and preg_match(
                '/^content-security-policy(-report-only)?$/',
                $name,
                $matches
            )
        ) {
            $this->importCSP($value, isset($matches[1]));
        }
        elseif ($this->allowImports and $name === 'strict-transport-security')
        {
            $this->importHSTS($value);
        }
        elseif (
            $this->allowImports
            and preg_match(
                '/^public-key-pins(-report-only)?$/',
                $name,
                $matches
            )
        ) {
            $this->importHPKP($value, isset($matches[1]));
        }
        # add the header, and disect its value
        else
        {
            $this->headers[$name] = array(
                'name' =>
                    $capitalisedName,
                'value' =>
                    $value,
                'attributes' =>
                    $this->deconstructHeaderValue($value, $name),
                'attributePositions' =>
                    $this->deconstructHeaderValue($value, $name, true)
            );
        }

        unset($this->removedHeaders[$name]);
    }

    public function header(
        $name,
        $value = null
    ) {
        $this->assertTypes(array('string' => array($name, $value)));

        $this->addHeader($name, $value);
    }

    public function removeHeader($name)
    {
        $this->assertTypes(array('string' => array($name)));

        $name = strtolower($name);
        $headers = $this->getHeaderAliases($name);

        if ( ! empty($headers))
        {
            foreach ($headers as $header)
            {
                unset($this->headers[$header]);
            }

            return true;
        }

        $this->removedHeaders[$name] = true;

        return false;
    }

    # ~~
    # public functions: cookies

    public function removeCookie($name)
    {
        $this->assertTypes(array('string' => array($name)));

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
        $this->assertTypes(array('string' => array($directive, $source)));

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
        $this->assertTypes(array('string' => array($directive)));

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
        $this->assertTypes(
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
        $this->assertTypes(
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
        $this->assertTypes(
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
        $this->assertTypes(
            array('string' => array($friendlyDirective, $string, $algo))
        );

        return $this->cspHash($friendlyDirective, $string, $algo, true, true);
    }

    # Content-Security-Policy: Nonce

    public function cspNonce($friendlyDirective, $reportOnly = null)
    {
        $this->assertTypes(array('string' => array($friendlyDirective)));

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
        $this->assertTypes(array('string' => array($friendlyDirective)));

        return $this->cspNonce($friendlyDirective, true);
    }

    # ~~
    # public functions: HSTS

    public function hsts(
        $maxAge = 31536000,
        $subdomains = false,
        $preload = false
    ) {
        $this->assertTypes(array('int|string' => array($maxAge)));

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
        $this->assertTypes(
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
        $this->assertTypes(
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
        $this->importHeaders();
        $this->applyAutomaticHeaders();

        $this->compileCSP();
        $this->compileHSTS();
        $this->compileHPKP();

        $this->removeHeaders();

        $this->applySafeMode();

        $this->sendHeaders();

        $this->reportMissingHeaders();
        $this->validateHeaders();
        $this->reportErrors();
    }

    public function errorReporting($mode)
    {
        $this->errorReporting = ($mode == true);
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

    public function headersAsString($mode = true)
    {
        $this->headersAsString = ($mode == true);
    }

    public function getHeadersAsString()
    {
        if ( ! $this->headersAsString) return;

        $reportingState = $this->errorReporting;
        $this->errorReporting = false;

        $this->done();
        $this->errorReporting = $reportingState;

        return $this->headersString;
    }

    # ~~
    # Private Functions

    # ~~
    # private functions: raw headers

    private function importHeaders()
    {
        if ($this->headersAsString)
        {
            $this->allowImports = false;
            return;
        }

        # first grab any headers out of already set PHP headers_list
        $headers = $this->pregMatchArray(
            '/^([^:]+)[:][ ](.*)$/i',
            headers_list(),
            1,
            2
        );

        # delete them (we'll set them again later)
        header_remove();

        # if any, add these to our internal header list
        foreach ($headers as $header)
        {
            $this->addHeader($header[0], $header[1]);
        }

        $this->allowImports = false;
    }

    private function importCSP($headerValue, $reportOnly)
    {
        $this->assertTypes(
            array(
                'string' => array($headerValue),
                'bool' => array($reportOnly)
            )
        );

        $directives = $this->deconstructHeaderValue(
            $headerValue,
            'content-security-policy'
        );

        $csp = array();

        foreach ($directives as $directive => $sourceString)
        {
            $sources = explode(' ', $sourceString);

            if ( ! empty($sources) and ! is_bool($sourceString))
            {
                $csp[$directive] = $sources;
            }
            else
            {
                $csp[] = $directive;
            }
        }

        $this->csp($csp, $reportOnly);
    }

    private function importHSTS($headerValue)
    {
        $this->assertTypes(array('string' => array($headerValue)));

        $hsts = $this->deconstructHeaderValue($headerValue);

        $settings
            = $this->safeModeUnsafeHeaders['strict-transport-security'];

        foreach ($settings as $setting => $default)
        {
            if ( ! isset($hsts[$setting]))
            {
                $hsts[$setting] = $default;
            }
        }

        $this->hsts(
            $hsts['max-age'],
            $hsts['includesubdomains'],
            $hsts['preload']
        );
    }

    private function importHPKP($headerValue, $reportOnly = null)
    {
        $this->assertTypes(
            array(
                'string' => array($headerValue),
                'bool' => array($reportOnly)
            )
        );

        $hpkp = $this->deconstructHeaderValue(
            $headerValue,
            'public-key-pins'
        );

        if (empty($hpkp['pin'])) return;

        $settings = $this->safeModeUnsafeHeaders['public-key-pins'];
        if ( ! isset($settings['report-uri'])) $settings['report-uri'] = null;

        foreach ($settings as $setting => $default)
        {
            if ( ! isset($hpkp[$setting]))
            {
                $hpkp[$setting] = $default;
            }
        }

        $this->hpkp(
            $hpkp['pin'],
            $hpkp['max-age'],
            $hpkp['includesubdomains'],
            $hpkp['report-uri']
        );
    }

    private function removeHeaders()
    {
        if ($this->headersAsString) return;

        foreach ($this->removedHeaders as $name => $value)
        {
            header_remove($name);
        }
    }

    private function sendHeaders()
    {
        $compiledHeaders = array();

        foreach ($this->headers as $key => $header)
        {
            $headerString
                =   $header['name']
                    . ($header['value'] === '' ? '' : ': ' . $header['value']);

            if ($this->headersAsString)
            {
                $compiledHeaders[] = $headerString;
            }
            else
            {
                header($headerString);
            }
        }

        foreach ($this->cookies as $name => $cookie)
        {
            if (isset($this->removedCookies[strtolower($name)]))
            {
                continue;
            }

            if ( ! isset($cookie['max-age']) and isset($cookie['expires']))
            {
                $cookie['max-age'] = strtotime($cookie['expires']);
            }
            elseif (isset($cookie['max-age']))
            {
                if ( ! isset($cookie['expires']))
                {
                    # RFC 1123 date, per:
                    # https://tools.ietf.org/html/rfc6265#section-4.1.1
                    $cookie['expires']
                        = gmdate(
                            'D, d M Y H:i:s T',
                            $cookie['max-age'] + time()
                        );
                }
            }

            $cookieAtt = array(
                'max-age',
                'path',
                'domain',
                'secure',
                'httponly'
            );

            foreach ($cookieAtt as $att)
            {
                if ( ! isset($cookie[$att])) $cookie[$att] = null;
            }

            # format: https://tools.ietf.org/html/rfc6265#section-4.1.1

            $headerString = 'Set-Cookie: '
                . $name . '=' . $cookie[0].'; '
                . (isset($cookie['expires']) ?
                    'Expires='.$cookie['expires'].'; ' : '')
                . (isset($cookie['max-age']) ?
                    'Max-Age='.$cookie['max-age'].'; ' : '')
                . (isset($cookie['domain']) ?
                    'Domain='.$cookie['domain'].'; ' : '')
                . (isset($cookie['path']) ?
                    'Path='.$cookie['path'].'; ' : '')
                . ( ! empty($cookie['secure']) ?
                    'Secure; ' : '')
                . ( ! empty($cookie['httponly']) ?
                    'HttpOnly; ' : '');

            # remove final '; '
            $headerString = substr($headerString, 0, -2);

            if ($this->headersAsString)
            {
                $compiledHeaders[] = $headerString;
            }
            else
            {
                header($headerString, false);
            }
        }

        if ($this->headersAsString)
        {
            $this->headersString = implode("\n", $compiledHeaders);
        }
    }

    private function deconstructHeaderValue(
        $header = null,
        $name = null,
        $getPosition = null
    ) {
        $this->assertTypes(
            array(
                'string' => array($header, $name),
                'bool' => array($getPosition)
            )
        );

        if ( ! isset($header)) return array();

        if ( ! isset($getPosition)) $n = 0;
        else $n = 1;

        $attributes = array();

        $storeMultipleValues = false;

        if (isset($name) and strpos($name, 'content-security-policy') !== false)
        {
            $headerRe = '/($^)|[; ]*([^; ]+)(?:(?:[ ])([^;]+)|)/';
        }
        elseif (isset($name) and strpos($name, 'public-key-pins') !== false)
        {
            $headerRe = '/["; ]*(?:(pin)-)?([^;=]+)(?:(?:="?)([^;"]+)|)/';
            $storeMultipleValues = true;
        }
        else
        {
            $headerRe = '/($^)|[; ]*([^;=]+)(?:(?:=)([^;]+)|)/';
        }

        if (
            preg_match_all(
                $headerRe,
                $header,
                $matches,
                PREG_SET_ORDER | PREG_OFFSET_CAPTURE
            )
        ) {
            foreach ($matches as $match)
            {
                if ( ! isset($match[3][0]))
                {
                    $match[3][$n] = ($n ? $match[2][$n] : true);
                }

                if ($storeMultipleValues and ! empty($match[1][0]))
                {
                    $attributes[strtolower($match[1][0])]
                        []= array($match[2][$n], $match[3][$n]);
                }
                # don't overwrite an existing entry
                elseif ( ! isset($attributes[strtolower($match[2][0])]))
                {
                    $attributes[strtolower($match[2][0])] = $match[3][$n];
                }
            }
        }

        return $attributes;
    }

    private function validateHeaders()
    {
        foreach ($this->headers as $header => $data)
        {
            $friendlyHeader = str_replace('-', ' ', $header);
            $friendlyHeader = ucwords($friendlyHeader);

            if (
                $header === 'content-security-policy'
                or $header === 'content-security-policy-report-only'
            ) {

                if (
                    $header === 'content-security-policy-report-only'
                    and (
                        ! isset($data['attributes']['report-uri'])
                        or  ! preg_match(
                            '/https:\/\/[a-z0-9\-]+[.][a-z]{2,}.*/i',
                            $data['attributes']['report-uri']
                        )
                    )
                ) {
                    $this->addError($friendlyHeader.' header was sent,
                        but an invalid, or no reporting address was given.
                        This header will not enforce violations, and with no
                        reporting address specified, the browser can only
                        report them locally in its console. Consider adding
                        a reporting address to make full use of this header.'
                    );
                }

                foreach ($data['attributes'] as $name => $value)
                {
                    if ($name === 'default-src' or $name === 'script-src')
                    {
                        $badFlags = array("'unsafe-inline'", "'unsafe-eval'");

                        foreach ($badFlags as $badFlag)
                        {
                            if (strpos($value, $badFlag) !== false)
                            {
                                $this->addError(
                                    $friendlyHeader.' contains the <b>'
                                    . $badFlag.'</b> keyword in <b>'.$name
                                    . '</b>, which prevents CSP protecting
                                    against the injection of arbitrary code
                                    into the page.',

                                    E_USER_WARNING
                                );
                            }
                        }
                    }

                    if (
                        preg_match_all(
                            $this->cspSourceWildcardRe,
                            $value,
                            $matches
                        )
                    ) {
                        if (
                            ! in_array($name, $this->cspSensitiveDirectives)
                        ) {
                            # if we're not looking at one of the above, we'll
                            # be a little less strict with data:
                            if (
                                (
                                    $key = array_search('data:', $matches[0])
                                ) !== false
                            ) {
                                unset($matches[0][$key]);
                            }
                        }

                        if ( ! empty($matches[0]))
                        {
                            $this->addError(
                                $friendlyHeader.' '.(count($matches[0]) > 1 ?
                                    'contains the following wildcards '
                                    : 'contains a wildcard ')
                                . '<b>'.implode(', ', $matches[0]).'</b> as a
                                source value in <b>'.$name.'</b>; this can
                                allow anyone to insert elements covered by
                                the <b>'.$name.'</b> directive into the
                                page.',

                                E_USER_WARNING
                            );
                        }
                    }

                    if (
                        preg_match_all(
                            '/(?:[ ]|^)\Khttp[:][^ ]*/',
                            $value,
                            $matches
                        )
                    ) {
                        $this->addError(
                            $friendlyHeader.' contains the insecure protocol
                            HTTP in '.(count($matches[0]) > 1 ?
                                'the following source values '
                                :  'a source value ')
                            . '<b>'.implode(', ', $matches[0]).'</b>; this can
                            allow anyone to insert elements covered by the
                            <b>'.$name.'</b> directive into the page.',

                            E_USER_WARNING
                        );
                    }
                }
            }
        }
    }

    # ~~ private functions: Cookies

    private function addCookie($name, $value = null, $extractCookie = null)
    {
        $this->assertTypes(array('string' => array($name, $value)));

        # if extractCookie loosely compares to true, the value will be
        # extracted from the cookie name e.g. the from the form
        # ('name=value; attribute=abc; attrib;')

        $cookie = array();

        if ($extractCookie)
        {
            if (
                preg_match_all(
                    '/[; ]*([^=; ]+)(?:(?:=)([^;]+)|)/',
                    $name,
                    $matches,
                    PREG_SET_ORDER
                )
            ) {
                $name = $matches[0][1];

                if (isset($matches[0][2]))
                {
                    $cookie[0] = $matches[0][2];
                }
                else
                {
                    $cookie[0] = '';
                }

                unset($matches[0]);

                foreach ($matches as $match)
                {
                    if ( ! isset($match[2])) $match[2] = true;

                    $cookie[strtolower($match[1])] = $match[2];
                }
            }
        }
        else
        {
            $cookie[0] = $value;
        }

        $this->cookies[$name] = $cookie;
    }

    # ~~
    # private functions: Content-Security-Policy (CSP)

    # Content-Security-Policy: Policy string additions

    private function cspAllow(
        $friendlyDirective,
        $friendlySource = null,
        $reportOnly = null
    ) {
        $this->assertTypes(
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

        $this->assertTypes(array('string' => array($friendlyDirective)));

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

        $this->assertTypes(array('string' => array($friendlySource)));

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
        $this->assertTypes(array('string' => array($directive, $source)));

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

    private function compileCSP()
    {
        $cspString = '';
        $csproString = '';

        $csp 	= $this->getCSPObject(false);
        $cspro  = $this->getCSPObject(true);

        # compile the CSP string

        foreach (array('csp', 'cspro') as $type)
        {
            foreach (${$type} as $directive => $sources)
            {
                $isFlag = ! isset($sources);

                $addToCSP
                    =   "$directive".($isFlag ?
                            ''
                            : ' '.implode(' ', $sources))
                        . '; ';

                if (
                    $type !== 'cspro'
                    or ! in_array($directive, $this->csproBlacklist)
                ) {
                    ${$type.'String'} .= $addToCSP;
                }
            }
        }

        if ( ! empty($cspString))
        {
            $cspString = substr($cspString, 0, -1);

            $this->addHeader('Content-Security-Policy', $cspString);

            if ($this->cspLegacy)
            {
                $this->addHeader('X-Content-Security-Policy', $cspString);
            }
        }

        if ( ! empty($csproString))
        {
            $csproString = substr($csproString, 0, -1);

            $this->addHeader(
                'Content-Security-Policy-Report-Only',
                $csproString
            );

            if ($this->cspLegacy)
            {
                $this->addHeader(
                    'X-Content-Security-Policy-Report-Only',
                    $csproString
                );
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
        $this->assertTypes(array('string' => array($directive)));

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
        $this->assertTypes(array('string' => array($string, $algo)));

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
        $nonce = base64_encode(openssl_random_pseudo_bytes(30, $isCryptoStrong));

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
    # private functions: HSTS

    private function compileHSTS()
    {
        if ( ! empty($this->hsts))
        {
            $this->addHeader(
                'Strict-Transport-Security',

                'max-age='.$this->hsts['max-age']
                . ($this->hsts['subdomains'] ? '; includeSubDomains' :'')
                . ($this->hsts['preload'] ? '; preload' :'')
            );
        }
    }

    # ~~
    # private functions: HPKP

    private function compileHPKP()
    {
        $hpkpString = '';
        $hpkproString = '';

        $hpkp 	 = &$this->getHPKPObject(false);
        $hpkpro  = &$this->getHPKPObject(true);

        foreach (array('hpkp', 'hpkpro') as $type)
        {
            if ( ! empty(${$type}) and ! empty(${$type}['pins']))
            {
                ${$type.'String'} = '';

                foreach (${$type}['pins'] as $pinAlg)
                {
                    list($pin, $alg) = $pinAlg;

                    ${$type.'String'} .= 'pin-' . $alg . '="' . $pin . '"; ';
                }

                if ( ! empty(${$type.'String'}))
                {
                    if ( ! isset(${$type}['max-age']))
                    {
                        ${$type}['max-age'] = 10;
                    }
                }
            }
        }

        if ( ! empty($hpkpString))
        {
            $this->addHeader(
                'Public-Key-Pins',

                'max-age='.$hpkp['max-age'] . '; '
                . $hpkpString
                . ($hpkp['includesubdomains'] ?
                    'includeSubDomains; ' :'')
                . ($hpkp['report-uri'] ?
                    'report-uri="' .$hpkp['report-uri']. '"' :'')
            );
        }

        if ( ! empty($hpkproString))
        {
            $this->addHeader(
                'Public-Key-Pins-Report-Only',

                'max-age='.$hpkpro['max-age'] . '; '
                . $hpkproString
                . ($hpkpro['includesubdomains'] ?
                    'includeSubDomains; ' :'')
                . ($hpkpro['report-uri'] ?
                    'report-uri="' .$hpkpro['report-uri']. '"' :'')
            );
        }
    }

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
    # private functions: Cookies

    private function modifyCookie($substr, $flag, $fullMatch = null)
    {
        $this->assertTypes(array('string' => array($substr, $flag)));

        if ( ! isset($fullMatch)) $fullMatch = false;

        foreach ($this->cookies as $cookieName => $cookie)
        {
            if (
                $fullMatch and $substr === strtolower($cookieName)
                or (
                    ! $fullMatch
                    and strpos(strtolower($cookieName), $substr) !== false
                )
            ) {
                $this->cookies[$cookieName][strtolower($flag)] = true;
            }
        }
    }

    # ~~
    # private functions: Safe Mode

    private function applySafeMode()
    {
        if ( ! $this->safeMode) return;

        foreach ($this->headers as $header => $data)
        {
            if (
                isset($this->safeModeUnsafeHeaders[$header])
                and empty($this->safeModeExceptions[$header])
            ) {
                $changed = false;

                foreach (
                    $this->safeModeUnsafeHeaders[$header]
                    as $attribute => $default
                ) {
                    # if the attribute is also set
                    if (isset($data['attributes'][$attribute]))
                    {
                        $value = $data['attributes'][$attribute];

                        # if the user-set value is a number, check to see if
                        # it's greater than safe mode's preference. If boolean
                        # or string check to see if the value differs
                        if (
                            (is_bool($default) or is_string($default))
                            and $default !== $value
                            or is_int($default) and intval($value) > $default
                        ) {
                            # if the default is a flag and true, we want the
                            # attribute name to be the default value
                            if (is_bool($default) and $default === true)
                            {
                                $default = $attribute;
                            }

                            $this->modifyHeaderValue(
                                $header,
                                $attribute,
                                $default,
                                true
                            );

                            # make note that we changed something
                            $changed = true;
                        }
                    }
                }

                # if we changed something, throw a notice to let user know
                if (
                    $changed
                    and isset($this->safeModeUnsafeHeaders[$header][0])
                ) {
                    $this->addError(
                        $this->safeModeUnsafeHeaders[$header][0],
                        E_USER_NOTICE
                    );
                }
            }
        }
    }

    private function modifyHeaderValue($header, $attribute, $newValue)
    {
        $this->assertTypes(array('string' => array($header, $attribute)));

        # if the attribute doesn't exist, dangerous to guess insersion method
        if ( ! isset($this->headers[$header]['attributes'][$attribute]))
        {
            return;
        }

        $currentValue = $this->headers[$header]['attributes'][$attribute];
        $currentOffset
            = $this->headers[$header]['attributePositions'][$attribute];

        # if the new value is a a flag, we want to replace the flag (attribute
        # text) otherwise, we're replacing the value of the attribute

        if (is_string($currentValue))
        {
            $currentLength = strlen($currentValue);
        }
        else
        {
            $currentLength = strlen($attribute);
        }

        $newLength = strlen($newValue);

        # perform the replacement
        $this->headers[$header]['value']
            =   substr_replace(
                    $this->headers[$header]['value'],
                    $newValue,
                    $currentOffset,
                    $currentLength
                );

        # in the case that a flag was removed, we may need to strip out a
        # delimiter too
        if (
            ! is_string($currentValue)
            and preg_match(
                '/^;[ ]?/',
                substr(
                    $this->headers[$header]['value'],
                    $currentOffset + $newLength,
                    2
                ),
                $match
            )
        ) {
            $tailLength = strlen($match[0]);

            $this->headers[$header]['value']
                =   substr_replace(
                        $this->headers[$header]['value'],
                        '',
                        $currentOffset + $newLength,
                        $tailLength
                    );

            $newLength -= $tailLength;
        }

        $lengthDiff = $newLength - $currentLength;

        # correct the positions of other attributes (replace may have varied
        # length of string)

        foreach (
            $this->headers[$header]['attributePositions'] as $i => $position
        ) {
            if ( ! is_int($position)) continue;

            if ($position > $currentOffset)
            {
                $this->headers[$header]['attributePositions'][$i]
                    += $lengthDiff;
            }
        }
    }

    # ~~
    # private functions: general

    private function addError($message, $error = E_USER_NOTICE)
    {
        $this->assertTypes(
            array('string' => array($message), 'int' => array($error))
        );

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

    private function pregMatchArray(
        $pattern,
        array $subjects,
        $valueCaptureGroup = null,
        $pairValueCaptureGroup = null
    ) {
        $this->assertTypes(
            array(
                'string' => array($pattern),
                'int' => array($valueCaptureGroup, $pairValueCaptureGroup)
            ),
            array(1, 3, 4)
        );

        if ( ! isset($valueCaptureGroup)) $valueCaptureGroup = 0;

        $matches = array();

        foreach ($subjects as $subject)
        {
            if (
                preg_match($pattern, $subject, $match)
                and isset($match[$valueCaptureGroup])
            ) {
                if ( ! isset($pairValueCaptureGroup))
                {
                    $matches[] = $match[$valueCaptureGroup];
                }
                else
                {
                    $matches[] = array(
                        $match[$valueCaptureGroup],
                        $match[$pairValueCaptureGroup]
                    );
                }
            }
        }

        return $matches;
    }

    private function isUnsafeHeader($name)
    {
        $this->assertTypes(array('string' => array($name)));

        return (
            $this->safeMode
            and isset($this->safeModeUnsafeHeaders[strtolower($name)])
        );
    }

    private function canInjectStrictDynamic()
    {
        # check if a relevant directive exists
        if (
            isset($this->csp[$directive = 'script-src'])
            or isset($this->csp[$directive = 'default-src'])
        ) {
            if (
                isset($this->csp[$directive]["'strict-dynamic'"])
                or isset($this->csp[$directive]["'none'"])
            ) {
                return -1;
            }

            $nonceOrHashRe = implode(
                '|',
                array_merge(
                    array('nonce'),
                    $this->allowedCSPHashAlgs
                )
            );

            # if the directive contains a nonce or hash, return the directive
            # that strict-dynamic should be injected into
            $nonceOrHash = preg_grep(
                "/^'(?:$nonceOrHashRe)-/i",
                array_keys($this->csp[$directive])
            );

            if ( ! empty($nonceOrHash))
            {
                return $directive;
            }
        }

        return false;
    }

    private function applyAutomaticHeaders()
    {
        $this->proposeHeaders = true;

        if ($this->strictMode)
        {
            $this->addHeader(
                'Strict-Transport-Security',
                'max-age=31536000; includeSubDomains; preload'
            );

            if (
                $this->safeMode
                and ! isset(
                    $this->safeModeExceptions['strict-transport-security']
                )
            ) {
                $this->addError(
                    'Strict-Mode is enabled, but so is Safe-Mode. HSTS with
                    long-duration, subdomains, and preload was added, but
                    Safe-Mode settings will take precedence if these settings
                    conflict.',

                    E_USER_NOTICE
                );
            }

            if (
                $directive = $this->canInjectStrictDynamic()
                and ! is_int($directive)
            ) {
                $this->csp($directive, 'strict-dynamic');
            }
            elseif ($directive !== -1)
            {
                $this->addError(
                    "<b>Strict-Mode</b> is enabled, but <b>'strict-dynamic'</b>
                    could not be added to the Content-Security-Policy because
                    no hash or nonce was used.",

                    E_USER_WARNING
                );
            }
        }

        if (($this->automaticHeaders & self::AUTO_ADD) === self::AUTO_ADD)
        {
            # security headers for all (HTTP and HTTPS) connections
            $this->addHeader('X-XSS-Protection', '1; mode=block');
            $this->addHeader('X-Content-Type-Options', 'nosniff');
            $this->addHeader('X-Frame-Options', 'Deny');
        }

        if (
            ($this->automaticHeaders & self::AUTO_REMOVE)
            === self::AUTO_REMOVE
        ) {
            # remove headers leaking server information
            $this->removeHeader('Server');
            $this->removeHeader('X-Powered-By');
        }

        if (
            ($this->automaticHeaders & self::AUTO_COOKIE_SECURE)
            === self::AUTO_COOKIE_SECURE
        ) {
            # add a secure flag to cookies that look like they hold session data
            foreach (
                $this->protectedCookies['substrings'] as $substr
            ) {
                $this->modifyCookie($substr, 'secure');
            }

            foreach ($this->protectedCookies['names'] as $name)
            {
                $this->modifyCookie($name, 'secure', true);
            }
        }

        if (
            ($this->automaticHeaders & self::AUTO_COOKIE_HTTPONLY)
            === self::AUTO_COOKIE_HTTPONLY
        ) {
            # add a httpOnly flag to cookies that look like they hold
            # session data
            foreach (
                $this->protectedCookies['substrings'] as $substr
            ) {
                $this->modifyCookie($substr, 'httpOnly');
            }

            foreach ($this->protectedCookies['names'] as $name)
            {
                $this->modifyCookie($name, 'httpOnly', true);
            }
        }

        $this->proposeHeaders = false;
    }

    private function errorHandler($level, $message)
    {
        $this->assertTypes(
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

    private function assertTypes(array $typeList, array $argNums = null)
    {
        $i = 0;
        $n = count($typeList);

        foreach ($typeList as $type => $vars)
        {
            if (is_array($vars)) $n += count($vars) - 1;
        }

        if ( ! isset($argNums)) $argNums = range(1, $n);

        $backtrace = debug_backtrace();
        $caller = $backtrace[1];

        foreach ($typeList as $type => $vars)
        {
            $type = strtolower($type);

            $type = preg_replace(
                array(
                    '/bool(?=$|[\|])/',
                    '/int(?=$|[\|])/'
                ),
                array(
                    'boolean',
                    'integer'
                ),
                $type
            );


            foreach ($vars as $var)
            {
                $allowedTypes = array_merge(
                    array('NULL'),
                    explode('|', $type)
                );

                if ( ! in_array(($varType = gettype($var)), $allowedTypes))
                {
                    $typeError
                        = new SecureHeadersTypeError(
                            'Argument '.$argNums[$i].' passed to '
                            .__CLASS__."::${caller['function']}() must be of"
                            ." the type $type, $varType given in "
                            ."${caller['file']} on line ${caller['line']}"
                        );

                    $typeError->passHeaders($this);

                    throw $typeError;
                }

                $i++;
            }
        }
    }

    private function getHeaderAliases($name)
    {
        $this->assertTypes(array('string' => array($name)));

        $headers = array_merge(
            $this->pregMatchArray(
                '/^'.preg_quote($name).'$/i',
                array_keys($this->headers)
            ),
            $this->pregMatchArray(
                '/^'.preg_quote($name).'(?=[:])/i',
                headers_list()
            )
        );

        if ( ! empty($headers))
        {
            return $headers;
        }

        return null;
    }

    private function reportMissingHeaders()
    {
        foreach ($this->reportMissingHeaders as $header)
        {
            if (empty($this->headers[strtolower($header)]))
            {
                $this->addError(
                    'Missing security header: ' . "'" . $header . "'",
                    E_USER_WARNING
                );
            }
        }
    }

    # ~~
    # private variables: (non settings)

    private $headers            = array();
    private $removedHeaders     = array();

    private $cookies            = array();
    private $removedCookies     = array();

    private $errors             = array();
    private $errorString;

    private $csp                = array();
    private $cspro              = array();

    private $cspNonces         = array(
        'enforced'      =>  array(),
        'reportOnly'    =>  array()
    );

    private $hsts               = array();

    private $hpkp               = array();
    private $hpkpro             = array();

    private $allowImports       = true;
    private $proposeHeaders     = false;

    private $isBufferReturned   = false;

    private $headersString;
    private $headersAsString    = false;

    private $doneOnOutput       = false;

    # private variables: (pre-defined static structures)

    private $cspDirectiveShortcuts = array(
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

    private $cspSourceShortcuts = array(
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

    protected $csproBlacklist = array(
        'block-all-mixed-content',
        'upgrade-insecure-requests'
    );

    private $allowedCSPHashAlgs = array(
        'sha256',
        'sha384',
        'sha512'
    );

    private $allowedHPKPAlgs = array(
        'sha256'
    );

    private $safeModeUnsafeHeaders = array(
        'strict-transport-security' => array(
            'max-age' => 86400,
            'includesubdomains' => false,
            'preload' => false,

            'HSTS settings were overridden because Safe-Mode is enabled.
            <a href="
            https://scotthelme.co.uk/death-by-copy-paste/#hstsandpreloading">
            Read about</a> some common mistakes when setting HSTS via
            copy/paste, and ensure you
            <a href="
            https://www.owasp.org/index.php/
            HTTP_Strict_Transport_Security_Cheat_Sheet">
            understand the details</a> and possible side effects of this
            security feature before using it.'
        ),
        'public-key-pins' => array(
            'max-age' => 10,
            'includesubdomains' => false,
            'Some HPKP settings were overridden because Safe-Mode is enabled.'
        )
    );

    private $reportMissingHeaders = array(
        'Strict-Transport-Security',
        'Content-Security-Policy',
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

        const AUTO_ADD              =  1; # 0b0001
        const AUTO_REMOVE           =  2; # 0b0010
        const AUTO_COOKIE_SECURE    =  4; # 0b0100
        const AUTO_COOKIE_HTTPONLY  =  8; # 0b1000
        const AUTO_ALL              = 15; # 0b1111

        # cookie upgrades

        const COOKIENAME           =  1; # 0b0001
        const COOKIE_SUBSTR         =  2; # 0b0010
        const COOKIE_ALL            =  3; # COOKIENAME | COOKIE_SUBSTR
        const COOKIE_REMOVE         =  4; # 0b0100
        const COOKIE_DEFAULT        =  2; # ~COOKIE_REMOVE & COOKIE_SUBSTR
}

class SecureHeadersTypeError extends Exception{
    private $headers;

    public function passHeaders(SecureHeaders $headers)
    {
        $this->headers = $headers;
    }

    public function __toString()
    {
        header($_SERVER['SERVER_PROTOCOL'].' 500 Internal Server Error');

        $this->headers->returnBuffer();

        return  'exception ' .__CLASS__. " '{$this->message}'\n"
                . "{$this->getTraceAsString()}";
    }
}
?>