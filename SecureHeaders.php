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
    # protected variables: settings

    protected $error_reporting = true;

    protected $csp_legacy = false;
    protected $return_existing_nonce = true;

    protected $strict_mode = false;

    protected $safe_mode = false;
    protected $safe_mode_exceptions = array();

    protected $automatic_headers = self::AUTO_ALL;

    protected $correct_header_name = true;

    protected $protected_cookies = array(
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

    public function done_on_output($mode = true)
    {
        if ($mode == true and $this->done_on_output === false)
        {
            ob_start(array($this, 'return_buffer'));

            $this->done_on_output = true;
        }
        elseif ($this->done_on_output === true)
        {
            ob_end_clean();

            $this->done_on_output = false;
        }
    }

    # ~~
    # public functions: settings

    # safe-mode enforces settings that shouldn't cause too much accidental
    # down-time safe-mode intentionally overwrites user specified settings

    public function safe_mode($mode = true)
    {
        if ($mode == false or strtolower($mode) === 'off')
        {
            $this->safe_mode = false;
        }
        else
        {
            $this->safe_mode = true;
        }
    }

    # if operating in safe mode, use this to manually allow a specific header

    public function safe_mode_exception($name)
    {
        $this->assert_types(array('string' => array($name)));

        $this->safe_mode_exceptions[strtolower($name)] = true;
    }

    public function strict_mode($mode = true)
    {
        if ($mode == false or strtolower($mode) === 'off')
        {
            $this->strict_mode = false;
        }
        else
        {
            $this->strict_mode = true;
        }
    }

    public function return_existing_nonce($mode = true)
    {
        $this->return_existing_nonce = ($mode == true);
    }

    public function auto($mode = self::AUTO_ALL)
    {
        $this->assert_types(array('int' => array($mode)));

        $this->automatic_headers = $mode;
    }

    public function correct_header_name($mode = true)
    {
        $this->correct_header_name = (true == $mode);
    }

    public function protected_cookie(
        $name,
        $mode = self::COOKIE_DEFAULT
    ) {
        $this->assert_types(
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
                $this->protected_cookie($cookie, $mode);
            }
            return;
        }

        $string_types = array();

        if (($mode & self::COOKIE_NAME) === self::COOKIE_NAME)
            $string_types[] = 'names';

        if (($mode & self::COOKIE_SUBSTR) === self::COOKIE_SUBSTR)
            $string_types[] = 'substrings';

        foreach ($string_types as $type)
        {
            if (
                ($mode & self::COOKIE_REMOVE) !== self::COOKIE_REMOVE
            and ! in_array($name, $this->protected_cookies[$type])
            ) {
                $this->protected_cookies[$type][] = $name;
            }
            elseif (
                ($mode & self::COOKIE_REMOVE) === self::COOKIE_REMOVE
                and (
                    $key = array_search(
                        $name,
                        $this->protected_cookies[$type]
                    )
                ) !== false
            ) {
                unset($this->protected_cookies[$type][$key]);
            }
        }
    }

    # ~~
    # public functions: raw headers

    public function add_header(
        $name,
        $value = null
    ) {
        $this->assert_types(array('string' => array($name, $value)));

        if (
            $this->correct_header_name
            and preg_match('/([^:]+)/', $name, $match)
        ) {
            $name = $match[1];
            
            $capitalised_name = preg_replace_callback(
                '/(?<=[-\s]|^)[^-\s]/',
                function ($match){
                    return strtoupper($match[0]);
                },
                $name
            );
        }
        else
        {
            $capitalised_name = $name;
        }

        $name = strtolower($name);

        if (
            $this->propose_headers
            and (
                isset($this->removed_headers[$name])
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
            $this->add_cookie($value, null, true);
        }
        # a few headers are better handled as an imported policy
        elseif (
            $this->allow_imports
            and preg_match(
                '/^content-security-policy(-report-only)?$/',
                $name,
                $matches
            )
        ) {
            $this->import_csp($value, isset($matches[1]));
        }
        elseif ($this->allow_imports and $name === 'strict-transport-security')
        {
            $this->import_hsts($value);
        }
        elseif (
            $this->allow_imports
            and preg_match(
                '/^public-key-pins(-report-only)?$/',
                $name,
                $matches
            )
        ) {
            $this->import_hpkp($value, isset($matches[1]));
        }
        # add the header, and disect its value
        else
        {
            $this->headers[$name] = array(
                'name' =>
                    $capitalised_name,
                'value' =>
                    $value,
                'attributes' =>
                    $this->deconstruct_header_value($value, $name),
                'attributePositions' =>
                    $this->deconstruct_header_value($value, $name, true)
            );
        }

        unset($this->removed_headers[$name]);
    }

    public function header(
        $name,
        $value = null
    ) {
        $this->assert_types(array('string' => array($name, $value)));

        $this->add_header($name, $value);
    }

    public function remove_header($name)
    {
        $this->assert_types(array('string' => array($name)));

        $name = strtolower($name);
        $headers = $this->get_header_aliases($name);

        if ( ! empty($headers))
        {
            foreach ($headers as $header)
            {
                unset($this->headers[$header]);
            }

            return true;
        }

        $this->removed_headers[$name] = true;

        return false;
    }

    # ~~
    # public functions: cookies

    public function remove_cookie($name)
    {
        $this->assert_types(array('string' => array($name)));

        unset($this->cookies[$name]);

        $this->removed_cookies[strtolower($name)] = true;
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
                $report_only = ($arg == true);
                break;
            }
        }
        # if no such items can be found, default to enforced csp
        if ( ! isset($report_only)) $report_only = false;

        # look at all the arguments
        for ($i = 0; $i < $num; $i++)
        {
            $arg = $args[$i];

            # if the arg is an array, then treat is as an entire policy
            if (is_array($arg))
            {
                $this->csp_array($arg, $report_only);
            }
            # if the arg is a string
            elseif (is_string($arg))
            {
                # then the arg is the directive name
                $friendly_directive = $arg;

                # if we've specified a source value (string: source,
                # or null: directive is flag)
                if (
                    ($i + 1 < $num)
                    and (is_string($args[$i+1]) or is_null($args[$i+1]))
                ) {
                    # then use the value we specified, and skip over the next
                    # item in the loop (since we just used it as a source value)
                    $friendly_source = $args[$i+1];
                    $i++;
                }
                # if no source is specified (either no more args, or one of
                # unsupported type)
                else
                {
                    # assume that the directive is a flag
                    $friendly_source = null;
                }

                $this->csp_allow(
                    $friendly_directive,
                    $friendly_source,
                    $report_only
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

    public function csp_legacy($mode = true)
    {
        $this->csp_legacy = ($mode == true);
    }

    # Content-Security-Policy: Policy string removals

    public function remove_csp_source($directive, $source, $report_only = null)
    {
        $this->assert_types(array('string' => array($directive, $source)));

        $csp = &$this->get_csp_object($report_only);

        $source = strtolower($source);
        $directive = strtolower($directive);

        if ( ! isset($csp[$directive][$source]))
        {
            return false;
        }

        unset($csp[$directive][$source]);

        return true;
    }

    public function remove_csp_directive($directive, $report_only = null)
    {
        $this->assert_types(array('string' => array($directive)));

        $csp = &$this->get_csp_object($report_only);

        $directive = strtolower($directive);

        if ( ! isset($csp[$directive]))
        {
            return false;
        }

        unset($csp[$directive]);

        return true;
    }

    public function reset_csp($report_only = null)
    {
        $csp = &$this->get_csp_object($report_only);

        $csp = array();
    }

    # Content-Security-Policy: Hashing

    public function csp_hash(
        $friendly_directive,
        $string,
        $algo = null,
        $is_file = null,
        $report_only = null
    ) {
        $this->assert_types(
            array('string' => array($friendly_directive, $string, $algo))
        );

        if (
            ! isset($algo)
            or ! in_array(
                strtolower($algo),
                $this->allowed_csp_hash_algs
            )
        ) {
            $algo = 'sha256';
        }

        $hash = $this->csp_do_hash($string, $algo, $is_file);

        $hash_string = "'$algo-$hash'";

        $this->csp_allow($friendly_directive, $hash_string, $report_only);

        return $hash;
    }

    public function cspro_hash(
        $friendly_directive,
        $string,
        $algo = null,
        $is_file = null
    ) {
        $this->assert_types(
            array('string' => array($friendly_directive, $string, $algo))
        );

        return $this->csp_hash(
            $friendly_directive,
            $string,
            $algo,
            $is_file,
            true
        );
    }

    public function csp_hash_file(
        $friendly_directive,
        $string,
        $algo = null,
        $report_only = null
    ) {
        $this->assert_types(
            array('string' => array($friendly_directive, $string, $algo))
        );

        return $this->csp_hash(
            $friendly_directive,
            $string,
            $algo,
            true,
            $report_only
        );
    }

    public function cspro_hash_file($friendly_directive, $string, $algo = null)
    {
        $this->assert_types(
            array('string' => array($friendly_directive, $string, $algo))
        );

        return $this->csp_hash($friendly_directive, $string, $algo, true, true);
    }

    # Content-Security-Policy: Nonce

    public function csp_nonce($friendly_directive, $report_only = null)
    {
        $this->assert_types(array('string' => array($friendly_directive)));

        $report_only = ($report_only == true);

        $nonce_store = &$this->csp_nonces[
            ($report_only ? 'report_only' : 'enforced')
        ];

        $directive = $this->long_directive($friendly_directive);

        if ($this->return_existing_nonce and isset($nonce_store[$directive]))
        {
            return $nonce_store[$directive];
        }

        $nonce = $this->csp_generate_nonce();

        $nonce_string = "'nonce-$nonce'";

        $this->add_csp_source($directive, $nonce_string, $report_only);

        $nonce_store[$directive] = $nonce;

        return $nonce;
    }

    public function cspro_nonce($friendly_directive)
    {
        $this->assert_types(array('string' => array($friendly_directive)));

        return $this->csp_nonce($friendly_directive, true);
    }

    # ~~
    # public functions: HSTS

    public function hsts(
        $max_age = 31536000,
        $subdomains = false,
        $preload = false
    ) {
        $this->assert_types(array('int|string' => array($max_age)));

        $this->hsts['max-age']      = $max_age;
        $this->hsts['subdomains']   = ($subdomains == true);
        $this->hsts['preload']      = ($preload == true);
    }

    public function hsts_subdomains($mode = true)
    {
        $this->hsts['subdomains'] = ($mode == true);
    }

    public function hsts_preload($mode = true)
    {
        $this->hsts['preload'] = ($mode == true);
    }

    # ~~
    # public functions: HPKP

    public function hpkp(
        $pins,
        $max_age = null,
        $subdomains = null,
        $report_uri = null,
        $report_only = null
    ) {
        $this->assert_types(
            array(
                'string|array' => array($pins),
                'int|string' => array($max_age),
                'string' => array($report_uri)
            ),
            array(1, 2, 4)
        );

        $hpkp = &$this->get_hpkp_object($report_only);

        # set single values

        if (isset($max_age) or ! isset($this->hpkp['max-age']))
        {
            $hpkp['max-age'] 	= $max_age;
        }

        if (isset($subdomains) or ! isset($this->hpkp['includesubdomains']))
        {
            $hpkp['includesubdomains']
                = (isset($subdomains) ? ($subdomains == true) : null);
        }

        if (isset($report_uri) or ! isset($this->hpkp['report-uri']))
        {
            $hpkp['report-uri'] = $report_uri;
        }

        if ( ! is_array($pins)) $pins = array($pins);

        # set pins

        foreach ($pins as $key => $pin)
        {
            if (is_array($pin) and count($pin) === 2)
            {
                $res = array_intersect($pin, $this->allowed_hpkp_algs);

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
        $max_age = null,
        $subdomains = null,
        $report_uri = null
    ) {
        $this->assert_types(
            array(
                'string|array' => array($pins),
                'int|string' => array($max_age),
                'string' => array($report_uri)
            ),
            array(1, 2, 4)
        );

        return $this->hpkp($pins, $max_age, $subdomains, $report_uri, true);
    }

    public function hpkp_subdomains($mode = true, $report_only = null)
    {
        $hpkp = &$this->get_hpkp_object($report_only);

        $hpkp['includesubdomains'] = ($mode == true);
    }

    public function hpkpro_subdomains($mode = true)
    {
        return $this->hpkp_subdomains($mode, true);
    }

    # ~~
    # public functions: general

    public function done()
    {
        $this->import_headers();
        $this->apply_automatic_headers();

        $this->compile_csp();
        $this->compile_hsts();
        $this->compile_hpkp();

        $this->remove_headers();

        $this->apply_safe_mode();

        $this->send_headers();

        $this->report_missing_headers();
        $this->validate_headers();
        $this->report_errors();
    }

    public function error_reporting($mode)
    {
        $this->error_reporting = ($mode == true);
    }

    # ~~
    # public functions: non-user
    #
    # These aren't documented because they aren't meant to be used directly,
    # but still need to have public visability.

    public function return_buffer($buffer = null)
    {
        if ($this->buffer_returned) return $buffer;

        $this->done();

        if (ob_get_level() and ! empty($this->error_string))
        {
            # prepend any errors to the buffer string (any errors that were
            # echoed will have been lost during an ob_start callback)
            $buffer = $this->error_string . $buffer;
        }

        # if we were called as part of ob_start, make note of this
        # (avoid doing redundent work if called again)
        $this->buffer_returned = true;

        return $buffer;
    }

    public function headers_as_string($mode = true)
    {
        $this->headers_as_string = ($mode == true);
    }

    public function get_headers_as_string()
    {
        if ( ! $this->headers_as_string) return;

        $reporting_state = $this->error_reporting;
        $this->error_reporting = false;

        $this->done();
        $this->error_reporting = $reporting_state;

        return $this->headers_string;
    }

    # ~~
    # Private Functions

    # ~~
    # private functions: raw headers

    private function import_headers()
    {
        if ($this->headers_as_string)
        {
            $this->allow_imports = false;
            return;
        }

        # first grab any headers out of already set PHP headers_list
        $headers = $this->preg_match_array(
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
            $this->add_header($header[0], $header[1]);
        }

        $this->allow_imports = false;
    }

    private function import_csp($header_value, $report_only)
    {
        $this->assert_types(
            array(
                'string' => array($header_value),
                'bool' => array($report_only)
            )
        );

        $directives = $this->deconstruct_header_value(
            $header_value,
            'content-security-policy'
        );

        $csp = array();

        foreach ($directives as $directive => $source_string)
        {
            $sources = explode(' ', $source_string);

            if ( ! empty($sources) and ! is_bool($source_string))
            {
                $csp[$directive] = $sources;
            }
            else
            {
                $csp[] = $directive;
            }
        }

        $this->csp($csp, $report_only);
    }

    private function import_hsts($header_value)
    {
        $this->assert_types(array('string' => array($header_value)));

        $hsts = $this->deconstruct_header_value($header_value);

        $settings
            = $this->safe_mode_unsafe_headers['strict-transport-security'];

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

    private function import_hpkp($header_value, $report_only = null)
    {
        $this->assert_types(
            array(
                'string' => array($header_value),
                'bool' => array($report_only)
            )
        );

        $hpkp = $this->deconstruct_header_value(
            $header_value,
            'public-key-pins'
        );

        if (empty($hpkp['pin'])) return;

        $settings = $this->safe_mode_unsafe_headers['public-key-pins'];
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

    private function remove_headers()
    {
        if ($this->headers_as_string) return;

        foreach ($this->removed_headers as $name => $value)
        {
            header_remove($name);
        }
    }

    private function send_headers()
    {
        $compiled_headers = array();

        foreach ($this->headers as $key => $header)
        {
            $header_string
                =   $header['name']
                    . ($header['value'] === '' ? '' : ': ' . $header['value']);

            if ($this->headers_as_string)
            {
                $compiled_headers[] = $header_string;
            }
            else
            {
                header($header_string);
            }
        }

        foreach ($this->cookies as $name => $cookie)
        {
            if (isset($this->removed_cookies[strtolower($name)]))
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

            $cookie_att = array(
                'max-age',
                'path',
                'domain',
                'secure',
                'httponly'
            );

            foreach ($cookie_att as $att)
            {
                if ( ! isset($cookie[$att])) $cookie[$att] = null;
            }

            # format: https://tools.ietf.org/html/rfc6265#section-4.1.1

            $header_string = 'Set-Cookie: '
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
            $header_string = substr($header_string, 0, -2);

            if ($this->headers_as_string)
            {
                $compiled_headers[] = $header_string;
            }
            else
            {
                header($header_string, false);
            }
        }

        if ($this->headers_as_string)
        {
            $this->headers_string = implode("\n", $compiled_headers);
        }
    }

    private function deconstruct_header_value(
        $header = null,
        $name = null,
        $get_position = null
    ) {
        $this->assert_types(
            array(
                'string' => array($header, $name),
                'bool' => array($get_position)
            )
        );

        if ( ! isset($header)) return array();

        if ( ! isset($get_position)) $n = 0;
        else $n = 1;

        $attributes = array();

        $store_multiple_values = false;

        if (isset($name) and strpos($name, 'content-security-policy') !== false)
        {
            $header_re = '/($^)|[; ]*([^; ]+)(?:(?:[ ])([^;]+)|)/';
        }
        elseif (isset($name) and strpos($name, 'public-key-pins') !== false)
        {
            $header_re = '/["; ]*(?:(pin)-)?([^;=]+)(?:(?:="?)([^;"]+)|)/';
            $store_multiple_values = true;
        }
        else
        {
            $header_re = '/($^)|[; ]*([^;=]+)(?:(?:=)([^;]+)|)/';
        }

        if (
            preg_match_all(
                $header_re,
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

                if ($store_multiple_values and ! empty($match[1][0]))
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

    private function validate_headers()
    {
        foreach ($this->headers as $header => $data)
        {
            $friendly_header = str_replace('-', ' ', $header);
            $friendly_header = ucwords($friendly_header);

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
                    $this->add_error($friendly_header.' header was sent,
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
                        $bad_flags = array("'unsafe-inline'", "'unsafe-eval'");

                        foreach ($bad_flags as $bad_flag)
                        {
                            if (strpos($value, $bad_flag) !== false)
                            {
                                $this->add_error(
                                    $friendly_header.' contains the <b>'
                                    . $bad_flag.'</b> keyword in <b>'.$name
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
                            $this->csp_source_wildcard_re,
                            $value,
                            $matches
                        )
                    ) {
                        if (
                            ! in_array($name, $this->csp_sensitive_directives)
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
                            $this->add_error(
                                $friendly_header.' '.(count($matches[0]) > 1 ?
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
                        $this->add_error(
                            $friendly_header.' contains the insecure protocol
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

    private function add_cookie($name, $value = null, $extract_cookie = null)
    {
        $this->assert_types(array('string' => array($name, $value)));

        # if extract_cookie loosely compares to true, the value will be
        # extracted from the cookie name e.g. the from the form
        # ('name=value; attribute=abc; attrib;')

        $cookie = array();

        if ($extract_cookie)
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

    private function csp_allow(
        $friendly_directive,
        $friendly_source = null,
        $report_only = null
    ) {
        $this->assert_types(
            array('string' => array($friendly_directive, $friendly_source))
        );

        $directive = $this->long_directive($friendly_directive);

        $source = $this->long_source($friendly_source);

        $this->add_csp_source($directive, $source, $report_only);
    }

    private function long_directive($friendly_directive)
    {
        # takes directive A and returns the corresponding long directive, if the
        # directive A is friendly directive. Otherwise, directive A will be
        # returned

        $this->assert_types(array('string' => array($friendly_directive)));

        $friendly_directive = strtolower($friendly_directive);

        if (isset($this->csp_directive_shortcuts[$friendly_directive]))
        {
            $directive = $this->csp_directive_shortcuts[$friendly_directive];
        }
        else
        {
            $directive = $friendly_directive;
        }

        return $directive;
    }

    private function long_source($friendly_source)
    {
        # takes source A and returns the corresponding long source, if the source A
        # is friendly source. Otherwise, source A will be returned

        $this->assert_types(array('string' => array($friendly_source)));

        $lower_friendly_source = strtolower($friendly_source);

        if (isset($this->csp_source_shortcuts[$lower_friendly_source]))
        {
            $source = $this->csp_source_shortcuts[$lower_friendly_source];
        }
        else
        {
            $source = $friendly_source;
        }

        return $source;
    }

    private function add_csp_source(
        $directive,
        $source = null,
        $report_only = null
    ) {
        $this->assert_types(array('string' => array($directive, $source)));

        $csp = &$this->get_csp_object($report_only);

        if ( ! isset($csp[$directive]))
        {
            $this->add_csp_directive(
                $directive,
                ! isset($source),
                $report_only
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

    private function csp_array(array $csp, $report_only = false)
    {
        foreach ($csp as $friendly_directive => $sources)
        {
            if (is_array($sources) and ! empty($sources))
            {
                foreach ($sources as $friendly_source)
                {
                    $this->csp_allow(
                        $friendly_directive,
                        $friendly_source,
                        $report_only
                    );
                }
            }
            elseif (is_int($friendly_directive) and is_string($sources))
            {
                # special case that $sources is actually a directive name,
                # with an int index
                $friendly_directive = $sources;

                # we'll treat this case as a CSP flag
                $this->csp_allow($friendly_directive, null, $report_only);
            }
            elseif ( ! is_array($sources))
            {
                # special case that $sources isn't an array (possibly a string
                # source, or null
                $this->csp_allow($friendly_directive, $sources, $report_only);
            }
        }
    }

    private function compile_csp()
    {
        $csp_string = '';
        $csp_ro_string = '';

        $csp 	= $this->get_csp_object(false);
        $csp_ro = $this->get_csp_object(true);

        # compile the CSP string

        foreach (array('csp', 'csp_ro') as $type)
        {
            foreach (${$type} as $directive => $sources)
            {
                $is_flag = ! isset($sources);

                $add_to_csp
                    =   "$directive".($is_flag ?
                            ''
                            : ' '.implode(' ', $sources))
                        . '; ';

                if (
                    $type !== 'csp_ro'
                    or ! in_array($directive, $this->csp_ro_blacklist)
                ) {
                    ${$type.'_string'} .= $add_to_csp;
                }
            }
        }

        if ( ! empty($csp_string))
        {
            $csp_string = substr($csp_string, 0, -1);

            $this->add_header('Content-Security-Policy', $csp_string);

            if ($this->csp_legacy)
            {
                $this->add_header('X-Content-Security-Policy', $csp_string);
            }
        }

        if ( ! empty($csp_ro_string))
        {
            $csp_ro_string = substr($csp_ro_string, 0, -1);

            $this->add_header(
                'Content-Security-Policy-Report-Only',
                $csp_ro_string
            );

            if ($this->csp_legacy)
            {
                $this->add_header(
                    'X-Content-Security-Policy-Report-Only',
                    $csp_ro_string
                );
            }
        }
    }

    private function &get_csp_object($report_only)
    {
        if ( ! isset($report_only) or ! $report_only)
        {
            $csp = &$this->csp;
        }
        else
        {
            $csp = &$this->csp_ro;
        }

        return $csp;
    }

    private function add_csp_directive(
        $directive,
        $is_flag = null,
        $report_only = null
    ) {
        $this->assert_types(array('string' => array($directive)));

        if ( ! isset($is_flag)) $is_flag = false;

        $csp = &$this->get_csp_object($report_only);

        if (isset($csp[$directive]))
        {
            return false;
        }

        if ( ! $is_flag) $csp[$directive] = array();
        else $csp[$directive] = null;

        return true;
    }

    private function csp_do_hash(
        $string,
        $algo = null,
        $is_file = null
    ) {
        $this->assert_types(array('string' => array($string, $algo)));

        if ( ! isset($algo)) $algo = 'sha256';

        if ( ! isset($is_file)) $is_file = false;

        if ( ! $is_file)
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
                $this->add_error(
                    __FUNCTION__.': The specified file'
                    . "<strong>'$string'</strong>, does not exist"
                );

                return '';
            }
        }

        return base64_encode($hash);
    }

    private function csp_generate_nonce()
    {
        $nonce = base64_encode(openssl_random_pseudo_bytes(30, $crypto_strong));

        if ( ! $crypto_strong)
        {
            $this->add_error(
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

    private function compile_hsts()
    {
        if ( ! empty($this->hsts))
        {
            $this->add_header(
                'Strict-Transport-Security',

                'max-age='.$this->hsts['max-age']
                . ($this->hsts['subdomains'] ? '; includeSubDomains' :'')
                . ($this->hsts['preload'] ? '; preload' :'')
            );
        }
    }

    # ~~
    # private functions: HPKP

    private function compile_hpkp()
    {
        $hpkp_string = '';
        $hpkp_ro_string = '';

        $hpkp 	 = &$this->get_hpkp_object(false);
        $hpkp_ro = &$this->get_hpkp_object(true);

        foreach (array('hpkp', 'hpkp_ro') as $type)
        {
            if ( ! empty(${$type}) and ! empty(${$type}['pins']))
            {
                ${$type.'_string'} = '';

                foreach (${$type}['pins'] as $pin_alg)
                {
                    list($pin, $alg) = $pin_alg;

                    ${$type.'_string'} .= 'pin-' . $alg . '="' . $pin . '"; ';
                }

                if ( ! empty(${$type.'_string'}))
                {
                    if ( ! isset(${$type}['max-age']))
                    {
                        ${$type}['max-age'] = 10;
                    }
                }
            }
        }

        if ( ! empty($hpkp_string))
        {
            $this->add_header(
                'Public-Key-Pins',

                'max-age='.$hpkp['max-age'] . '; '
                . $hpkp_string
                . ($hpkp['includesubdomains'] ?
                    'includeSubDomains; ' :'')
                . ($hpkp['report-uri'] ?
                    'report-uri="' .$hpkp['report-uri']. '"' :'')
            );
        }

        if ( ! empty($hpkp_ro_string))
        {
            $this->add_header(
                'Public-Key-Pins-Report-Only',

                'max-age='.$hpkp_ro['max-age'] . '; '
                . $hpkp_ro_string
                . ($hpkp_ro['includesubdomains'] ?
                    'includeSubDomains; ' :'')
                . ($hpkp_ro['report-uri'] ?
                    'report-uri="' .$hpkp_ro['report-uri']. '"' :'')
            );
        }
    }

    private function &get_hpkp_object($report_only)
    {
        if ( ! isset($report_only) or ! $report_only)
        {
            $hpkp = &$this->hpkp;
        }
        else
        {
            $hpkp = &$this->hpkp_ro;
        }

        return $hpkp;
    }

    # ~~
    # private functions: Cookies

    private function modify_cookie($substr, $flag, $full_match = null)
    {
        $this->assert_types(array('string' => array($substr, $flag)));

        if ( ! isset($full_match)) $full_match = false;

        foreach ($this->cookies as $cookie_name => $cookie)
        {
            if (
                $full_match and $substr === strtolower($cookie_name)
                or (
                    ! $full_match
                    and strpos(strtolower($cookie_name), $substr) !== false
                )
            ) {
                $this->cookies[$cookie_name][strtolower($flag)] = true;
            }
        }
    }

    # ~~
    # private functions: Safe Mode

    private function apply_safe_mode()
    {
        if ( ! $this->safe_mode) return;

        foreach ($this->headers as $header => $data)
        {
            if (
                isset($this->safe_mode_unsafe_headers[$header])
                and empty($this->safe_mode_exceptions[$header])
            ) {
                $changed = false;

                foreach (
                    $this->safe_mode_unsafe_headers[$header]
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

                            $this->modify_header_value(
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
                    and isset($this->safe_mode_unsafe_headers[$header][0])
                ) {
                    $this->add_error(
                        $this->safe_mode_unsafe_headers[$header][0],
                        E_USER_NOTICE
                    );
                }
            }
        }
    }

    private function modify_header_value($header, $attribute, $new_value)
    {
        $this->assert_types(array('string' => array($header, $attribute)));

        # if the attribute doesn't exist, dangerous to guess insersion method
        if ( ! isset($this->headers[$header]['attributes'][$attribute]))
        {
            return;
        }

        $current_value = $this->headers[$header]['attributes'][$attribute];
        $current_offset
            = $this->headers[$header]['attributePositions'][$attribute];

        # if the new value is a a flag, we want to replace the flag (attribute
        # text) otherwise, we're replacing the value of the attribute

        if (is_string($current_value))
        {
            $current_length = strlen($current_value);
        }
        else
        {
            $current_length = strlen($attribute);
        }

        $new_length = strlen($new_value);

        # perform the replacement
        $this->headers[$header]['value']
            =   substr_replace(
                    $this->headers[$header]['value'],
                    $new_value,
                    $current_offset,
                    $current_length
                );

        # in the case that a flag was removed, we may need to strip out a
        # delimiter too
        if (
            ! is_string($current_value)
            and preg_match(
                '/^;[ ]?/',
                substr(
                    $this->headers[$header]['value'],
                    $current_offset + $new_length,
                    2
                ),
                $match
            )
        ) {
            $tail_length = strlen($match[0]);

            $this->headers[$header]['value']
                =   substr_replace(
                        $this->headers[$header]['value'],
                        '',
                        $current_offset + $new_length,
                        $tail_length
                    );

            $new_length -= $tail_length;
        }

        $length_diff = $new_length - $current_length;

        # correct the positions of other attributes (replace may have varied
        # length of string)

        foreach (
            $this->headers[$header]['attributePositions'] as $i => $position
        ) {
            if ( ! is_int($position)) continue;

            if ($position > $current_offset)
            {
                $this->headers[$header]['attributePositions'][$i]
                    += $length_diff;
            }
        }
    }

    # ~~
    # private functions: general

    private function add_error($message, $error = E_USER_NOTICE)
    {
        $this->assert_types(
            array('string' => array($message), 'int' => array($error))
        );

        $message = preg_replace('/\s+/', ' ', $message);

        $this->errors[] = array($message, $error);
    }

    private function report_errors()
    {
        if ( ! $this->error_reporting) return;

        set_error_handler(array(get_class(), 'error_handler'));

        if ( ! empty($this->errors)) $this->buffer_returned = true;

        foreach ($this->errors as $msg_lvl)
        {
            list($message, $level) = $msg_lvl;

            trigger_error($message, $level);
        }

        restore_error_handler();
    }

    private function preg_match_array(
        $pattern,
        array $subjects,
        $value_capture_group = null,
        $pair_value_capture_group = null
    ) {
        $this->assert_types(
            array(
                'string' => array($pattern),
                'int' => array($value_capture_group, $pair_value_capture_group)
            ),
            array(1, 3, 4)
        );

        if ( ! isset($value_capture_group)) $value_capture_group = 0;

        $matches = array();

        foreach ($subjects as $subject)
        {
            if (
                preg_match($pattern, $subject, $match)
                and isset($match[$value_capture_group])
            ) {
                if ( ! isset($pair_value_capture_group))
                {
                    $matches[] = $match[$value_capture_group];
                }
                else
                {
                    $matches[] = array(
                        $match[$value_capture_group],
                        $match[$pair_value_capture_group]
                    );
                }
            }
        }

        return $matches;
    }

    private function is_unsafe_header($name)
    {
        $this->assert_types(array('string' => array($name)));

        return (
            $this->safe_mode
            and isset($this->safe_mode_unsafe_headers[strtolower($name)])
        );
    }

    private function can_inject_strict_dynamic()
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

            $nonce_or_hash_re = implode(
                '|',
                array_merge(
                    array('nonce'),
                    $this->allowed_csp_hash_algs
                )
            );

            # if the directive contains a nonce or hash, return the directive
            # that strict-dynamic should be injected into
            $nonce_or_hash = preg_grep(
                "/^'(?:$nonce_or_hash_re)-/i",
                array_keys($this->csp[$directive])
            );

            if ( ! empty($nonce_or_hash))
            {
                return $directive;
            }
        }

        return false;
    }

    private function apply_automatic_headers()
    {
        $this->propose_headers = true;

        if ($this->strict_mode)
        {
            $this->add_header(
                'Strict-Transport-Security',
                'max-age=31536000; includeSubDomains; preload'
            );

            if (
                $this->safe_mode
                and ! isset(
                    $this->safe_mode_exceptions['strict-transport-security']
                )
            ) {
                $this->add_error(
                    'Strict-Mode is enabled, but so is Safe-Mode. HSTS with
                    long-duration, subdomains, and preload was added, but
                    Safe-Mode settings will take precedence if these settings
                    conflict.',

                    E_USER_NOTICE
                );
            }

            if (
                $directive = $this->can_inject_strict_dynamic()
                and ! is_int($directive)
            ) {
                $this->csp($directive, 'strict-dynamic');
            }
            elseif ($directive !== -1)
            {
                $this->add_error(
                    "<b>Strict-Mode</b> is enabled, but <b>'strict-dynamic'</b>
                    could not be added to the Content-Security-Policy because
                    no hash or nonce was used.",

                    E_USER_WARNING
                );
            }
        }

        if (($this->automatic_headers & self::AUTO_ADD) === self::AUTO_ADD)
        {
            # security headers for all (HTTP and HTTPS) connections
            $this->add_header('X-XSS-Protection', '1; mode=block');
            $this->add_header('X-Content-Type-Options', 'nosniff');
            $this->add_header('X-Frame-Options', 'Deny');
        }

        if (($this->automatic_headers & self::AUTO_REMOVE) === self::AUTO_REMOVE)
        {
            # remove headers leaking server information
            $this->remove_header('Server');
            $this->remove_header('X-Powered-By');
        }

        if (
            ($this->automatic_headers & self::AUTO_COOKIE_SECURE)
            === self::AUTO_COOKIE_SECURE
        ) {
            # add a secure flag to cookies that look like they hold session data
            foreach (
                $this->protected_cookies['substrings'] as $substr
            ) {
                $this->modify_cookie($substr, 'secure');
            }

            foreach ($this->protected_cookies['names'] as $name)
            {
                $this->modify_cookie($name, 'secure', true);
            }
        }

        if (
            ($this->automatic_headers & self::AUTO_COOKIE_HTTPONLY)
            === self::AUTO_COOKIE_HTTPONLY
        ) {
            # add a httpOnly flag to cookies that look like they hold
            # session data
            foreach (
                $this->protected_cookies['substrings'] as $substr
            ) {
                $this->modify_cookie($substr, 'httpOnly');
            }

            foreach ($this->protected_cookies['names'] as $name)
            {
                $this->modify_cookie($name, 'httpOnly', true);
            }
        }

        $this->propose_headers = false;
    }

    private function error_handler($level, $message)
    {
        $this->assert_types(
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
                $this->error_string .= $error;
                return true;
            }
        }
        return false;
    }

    private function assert_types(array $type_list, array $arg_nums = null)
    {
        $i = 0;
        $n = count($type_list);

        foreach ($type_list as $type => $vars)
        {
            if (is_array($vars)) $n += count($vars) - 1;
        }

        if ( ! isset($arg_nums)) $arg_nums = range(1, $n);

        $backtrace = debug_backtrace();
        $caller = $backtrace[1];

        foreach ($type_list as $type => $vars)
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
                $allowed_types = array_merge(
                    array('NULL'),
                    explode('|', $type)
                );

                if ( ! in_array(($var_type = gettype($var)), $allowed_types))
                {
                    $typeError
                        = new SecureHeadersTypeError(
                            'Argument '.$arg_nums[$i].' passed to '
                            .__CLASS__."::${caller['function']}() must be of"
                            ." the type $type, $var_type given in "
                            ."${caller['file']} on line ${caller['line']}"
                        );

                    $typeError->passHeaders($this);

                    throw $typeError;
                }

                $i++;
            }
        }
    }

    private function get_header_aliases($name)
    {
        $this->assert_types(array('string' => array($name)));

        $headers = array_merge(
            $this->preg_match_array(
                '/^'.preg_quote($name).'$/i',
                array_keys($this->headers)
            ),
            $this->preg_match_array(
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

    private function report_missing_headers()
    {
        foreach ($this->report_missing_headers as $header)
        {
            if (empty($this->headers[strtolower($header)]))
            {
                $this->add_error(
                    'Missing security header: ' . "'" . $header . "'",
                    E_USER_WARNING
                );
            }
        }
    }

    # ~~
    # private variables: (non settings)

    private $headers            = array();
    private $removed_headers    = array();

    private $cookies            = array();
    private $removed_cookies    = array();

    private $errors             = array();
    private $error_string;

    private $csp                = array();
    private $csp_ro             = array();
    private $csp_nonces         = array(
        'enforced' => array(),
        'report_only' => array()
    );

    private $hsts               = array();

    private $hpkp               = array();
    private $hpkp_ro            = array();

    private $allow_imports      = true;
    private $propose_headers    = false;

    private $buffer_returned    = false;

    private $headers_string;
    private $headers_as_string  = false;

    private $done_on_output     = false;

    # private variables: (pre-defined static structures)

    private $csp_directive_shortcuts = array(
        'default'   =>  'default-src',
        'script'    =>  'script-src',
        'style'     =>  'style-src',
        'image'     =>  'img-src',
        'img'       =>  'img-src',
        'font'      =>  'font-src',
        'child'     =>  'child-src',
        'base'      =>  'base-uri',
        'connect'   =>  'connect-src',
        'form'      =>  'form-action',
        'object'    =>  'object-src',
        'report'    =>  'report-uri',
        'reporting' =>  'report-uri'
    );

    private $csp_source_shortcuts = array(
        'self'              => "'self'",
        'none'              => "'none'",
        'unsafe-inline'     => "'unsafe-inline'",
        'unsafe-eval'       => "'unsafe-eval'",
        'strict-dynamic'    => "'strict-dynamic'",
    );

    private $csp_sensitive_directives = array(
        'default-src',
        'script-src',
        'style-src',
        'object-src'
    );

    protected $csp_ro_blacklist = array(
        'block-all-mixed-content',
        'upgrade-insecure-requests'
    );

    private $allowed_csp_hash_algs = array(
        'sha256',
        'sha384',
        'sha512'
    );

    private $allowed_hpkp_algs = array(
        'sha256'
    );

    private $safe_mode_unsafe_headers = array(
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

    private $report_missing_headers = array(
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-XSS-Protection',
        'X-Content-Type-Options',
        'X-Frame-Options'
    );

    private $csp_source_wildcard_re
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

        const COOKIE_NAME           =  1; # 0b0001
        const COOKIE_SUBSTR         =  2; # 0b0010
        const COOKIE_ALL            =  3; # COOKIE_NAME | COOKIE_SUBSTR
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

        $this->headers->return_buffer();

        return  'exception ' .__CLASS__. " '{$this->message}'\n"
                . "{$this->getTraceAsString()}";
    }
}
?>