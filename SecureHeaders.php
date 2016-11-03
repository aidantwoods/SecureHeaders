<?php

class SecureHeaders{
    # ~~
    # private variables: settings

    private $error_reporting = true;
 
    private $csp_ro_blacklist = array(
        'block-all-mixed-content',
        'upgrade-insecure-requests'
    );

    private $csp_legacy = false;

    private $safe_mode = false;
    private $safe_mode_exceptions = array();

    private $allowed_hpkp_algs = array(
        'sha256'
    );

    private $automatic_headers = array(
        'add' => true,
        'remove' => true,
        'secure-session-cookie' => true,
        'safe-session-cookie' => true
    );

    private $protected_cookie_identifiers = array(
        'substrings' => array(
            'sess',
            'auth',
            'login',
            'csrf',
            'token'
        ),
        'names' => array(
            'sid',
            's',
            'persistent'
        )
    );

    private $report_missing_headers = array(
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-XSS-Protection',
        'X-Content-Type-Options',
        'X-Frame-Options'
    );

    # ~~
    # Public Functions

    # ~~
    # public functions: settings

    /**
     * safe-mode enforces settings that shouldn't cause too much accidental down-time
     * safe-mode intentionally overwrites user specified settings
     */
    public function safe_mode($mode = null)
    {
        if ($mode === false or strtolower($mode) === 'off')
            $this->safe_mode = false;
        else
            $this->safe_mode = true;
    }

    # if operating in safe mode, use this to manually allow a specific header

    public function safe_mode_exception($name)
    {
        $this->assert_types(array('string' => [$name]));

        $this->safe_mode_exceptions[strtolower($name)] = true;
    }

    public function add_automatic_headers($mode = null)
    {
        foreach ($this->automatic_headers as $name => $state)
        {
            if (    ! isset($mode) 
                or
                ( 
                    is_string($mode) and $name === strtolower($mode)
                )
                or
                (
                    is_array($mode) and ! empty(preg_grep('/^'.preg_quote($name).'$/i', $mode))
                )
            ){
                $this->automatic_headers[$name] = true;
            }
        }
    }

    public function remove_automatic_headers($mode = null)
    {
        foreach ($this->automatic_headers as $name => $state)
        {
            if (    ! isset($mode) 
                or
                ( 
                    is_string($mode) and $name === strtolower($mode)
                )
                or
                (
                    is_array($mode) and ! empty(preg_grep('/^'.preg_quote($name).'$/i', $mode))
                )
            ){
                $this->automatic_headers[$name] = false;
            }
        }
    }

    public function add_protected_cookie_name($name)
    {
        $this->assert_types(array('string' => [$name]));

        if ( ! in_array(strtolower($name), $this->protected_cookie_identifiers['names']))
        {
            $this->protected_cookie_identifiers['names'][] = strtolower($name);
        }
    }

    public function remove_protected_cookie_name($name)
    {
        $this->assert_types(array('string' => [$name]));

        if (($key = array_search(strtolower($name), $this->protected_cookie_identifiers['names'])) !== false)
        {
            unset($this->protected_cookie_identifiers['names'][$key]);
        }
    }

    public function add_protected_cookie_substring($substr)
    {
        $this->assert_types(array('string' => [$substr]));

        if ( ! in_array(strtolower($substr), $this->protected_cookie_identifiers['substrings']))
        {
            $this->protected_cookie_identifiers['substrings'][] = strtolower($substr);
        }
    }

    public function remove_protected_cookie_substring($substr)
    {
        $this->assert_types(array('string' => [$substr]));

        if (($key = array_search(strtolower($substr), $this->protected_cookie_identifiers['substrings'])) !== false)
        {
            unset($this->protected_cookie_identifiers['substrings'][$key]);
        }
    }

    # ~~
    # public functions: raw headers

    public function add_header($name, $value = null, $attempt_name_correction = null)
    {
        $this->assert_types(array('string' => [$name, $value], 'bool' => [$attempt_name_correction]));

        if ($this->propose_headers and isset($this->removed_headers[strtolower($name)]))
        {
            # a proposal header will only be added if the intented header
            # has not been staged for removal
            return;
        }

        if ( ! isset($attempt_name_correction)) $attempt_name_correction = true;

        if ( ! isset($auto_caps)) $auto_caps = true;

        if ($attempt_name_correction and preg_match('/([^:]+)/', $name, $match))
        {
            $name = $match[1];
        }

        $capitalised_name = $name;

        $name = strtolower($name);

        # if its actually a cookie, this requires special handling
        if ($name === 'set-cookie')
        {
            $this->add_cookie($value, null, true);
        }
        # a few headers are better handled as an imported policy
        elseif ($this->allow_imports and preg_match('/^content-security-policy(-report-only)?$/', $name, $matches))
        {
            $this->import_csp($value, isset($matches[1]));
        }
        elseif ($this->allow_imports and $name === 'strict-transport-security')
        {
            $this->import_hsts($value);
        }
        elseif ($this->allow_imports and preg_match('/^public-key-pins(-report-only)?$/', $name, $matches))
        {
            $this->import_hpkp($value, isset($matches[1]));
        }
        # add the header, and disect its value
        else
        {
            $this->headers[$name] = array(
                'name' => $capitalised_name,
                'value' => $value,
                'attributes' => $this->deconstruct_header_value($value, $name),
                'attributePositions' => $this->deconstruct_header_value($value, $name, true)
            );
        }

        unset($this->removed_headers[$name]);
    }

    public function remove_header($name)
    {
        $this->assert_types(array('string' => [$name]));

        $name = strtolower($name);

        if (! empty($headers = $this->get_header_aliases($name)))
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

    public function add_cookie(string $name, string $value = null, $extract_cookie = null)
    {
        $this->assert_types(array('string' => [$name, $value]));

        # if extract_cookie loosely compares to true, the value will be extracted from
        # the cookie name e.g. the from the form ('name=value; attribute=abc; attrib;')

        $cookie = array();

        if ($extract_cookie)
        {
            if (preg_match_all('/[; ]*([^=; ]+)(?:(?:=)([^;]+)|)/', $name, $matches, PREG_SET_ORDER))
            {
                $name = $matches[0][1];

                if (isset($matches[0][2]))  $cookie[0] = $matches[0][2];
                else                        $cookie[0] = '';

                unset($matches[0]);

                foreach ($matches as $match)
                {
                    if ( ! isset($match[2])) $match[2] = null;

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

    public function remove_cookie($name)
    {
        $this->assert_types(array('string' => [$name]));

        unset($this->cookies[$name]);
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

            # if the arg is an array, then treat is as an entire policy and move on
            if (is_array($arg))
            {
                $this->csp_array($arg, $report_only);
            }
            # if the arg is a string
            elseif (is_string($arg))
            {
                # then the arg is the directive name
                $friendly_directive = $arg;

                # if we've specified a source value (string: source, or null: directive is flag)
                if (($i + 1 < $num) and (is_string($args[$i+1]) or is_null($args[$i+1])))
                {
                    # then use the value we specified, and skip over the next item in the loop
                    # (since we just used it as a source value)
                    $friendly_source = $args[$i+1];
                    $i++;
                }
                # if no source is specified (either no more args, or one of unsupported type)
                else
                {
                    # assume that the directive is a flag
                    $friendly_source = null;
                }

                $this->csp_allow($friendly_directive, $friendly_source, $report_only);
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

    public function add_csp_legacy()
    {
        $this->csp_legacy = true;
    }

    public function remove_csp_legacy()
    {
        $this->csp_legacy = false;
    }

    # Content-Security-Policy: Policy string removals

    public function remove_csp_source($directive, $source, $report_only = null)
    {
        $this->assert_types(array('string' => [$directive, $source]));

        $csp = &$this->get_csp_object($report_only);

        if( ! isset($csp[$directive]))
        {
            return false;
        }
        
        unset($csp[$directive][$source]);

        return true;
    }

    public function remove_csp_directive($directive, $report_only = null)
    {
        $this->assert_types(array('string' => [$directive]));
        
        $csp = &$this->get_csp_object($report_only);

        if( ! isset($csp[$directive]))
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

    public function csp_hash($friendly_directive, $string, $algo = null, $is_file = null, $report_only = null)
    {
        $this->assert_types(array('string' => [$friendly_directive, $string, $algo]));

        if ( ! isset($algo)) $algo = 'sha256';

        $hash = $this->csp_do_hash($string, $algo, $is_file);

        $hash_string = "'$algo-" . $hash ."'";

        $this->csp_allow($friendly_directive, $hash_string, $report_only);

        return $hash;
    }

    public function cspro_hash($friendly_directive, $string, $algo = null, $is_file = null)
    {
        $this->assert_types(array('string' => [$friendly_directive, $string, $algo]));

        return $this->csp_hash($friendly_directive, $string, $algo, $is_file, true);
    }

    public function csp_hash_file($friendly_directive, $string, $algo = null, $report_only = null)
    {
        $this->assert_types(array('string' => [$friendly_directive, $string, $algo]));

        return $this->csp_hash($friendly_directive, $string, $algo, true, $report_only);
    }

    public function cspro_hash_file($friendly_directive, $string, $algo = null)
    {
        $this->assert_types(array('string' => [$friendly_directive, $string, $algo]));

        return $this->csp_hash($friendly_directive, $string, $algo, true, true);
    }
 
    # Content-Security-Policy: Nonce

    public function csp_nonce($friendly_directive, $report_only = null)
    {
        $this->assert_types(array('string' => [$friendly_directive]));

        $nonce = $this->csp_generate_nonce();

        $nonce_string = "'nonce-$nonce'";

        $this->csp_allow($friendly_directive, $nonce_string, $report_only);

        return $nonce;
    }

    public function cspro_nonce($friendly_directive)
    {
        $this->assert_types(array('string' => [$friendly_directive]));

        return $this->csp_nonce($friendly_directive, true);
    }

    # ~~
    # public functions: HSTS

    public function hsts($max_age = null, $subdomains = false, $preload = false)
    {
        $this->hsts['max-age']      = $max_age;
        $this->hsts['subdomains']   = ($subdomains == true);
        $this->hsts['preload']      = ($preload == true);
    }

    public function hsts_subdomains($mode = null)
    {
        if ($mode == false)
            $this->hsts['subdomains'] = false;
        else
            $this->hsts['subdomains'] = true;
    }

    public function hsts_preload($mode = null)
    {
        if ($mode == false)
            $this->hsts['preload'] = false;
        else
            $this->hsts['preload'] = true;
    }

    # ~~
    # public functions: HPKP

    public function hpkp(array $pins, $max_age = null, $subdomains = null, $report_uri = null)
    {
        $this->assert_types(array('string' => [$report_uri]), array(4));

        if(isset($max_age) or ! isset($this->hpkp['max-age'])) 
            $this->hpkp['max-age'] 	= $max_age;

        if(isset($subdomains) or ! isset($this->hpkp['includesubdomains'])) 
            $this->hpkp['includesubdomains'] = (isset($subdomains) ? ($subdomains == true) : null);
        
        if(isset($report_uri) or ! isset($this->hpkp['report-uri'])) 
            $this->hpkp['report-uri'] = $report_uri;

        foreach ($pins as $key => $pin)
        {
            if (is_array($pin) and count($pin) === 2)
            {
                if ( ! empty($res = array_intersect($pin, $this->allowed_hpkp_algs)))
                {
                    $key = key($res);
                    $this->hpkp['pins'][] = array($pin[($key + 1) % 2], $pin[$key]);
                }
                else
                {
                    continue;
                }
            }
            elseif ( ! is_array($pin) or (count($pin) === 1 and ($pin = $pin[0]) !== false))
            {
                $this->hpkp['pins'][] = array($pin, 'sha256');
            }
        }
    }

    public function hpkp_subdomains($mode = null)
    {
        if ($mode == false)
            $this->hpkp['includesubdomains'] = false;
        else
            $this->hpkp['includesubdomains'] = true;
    }

    # ~~
    # public functions: general

    public function done()
    {
        $this->import_headers();
        $this->automatic_headers();

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
        if ($mode == false)
            $this->error_reporting = false;
        else
            $this->error_reporting = true;
    }

    # ~~
    # Private Functions

    # ~~
    # private functions: raw headers

    private function import_headers()
    {
        # first grab any headers out of already set PHP headers_list
        $headers = $this->preg_match_array('/^([^:]+)[:][ ](.*)$/i', headers_list(), 1, 2);

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
        $this->assert_types(array('string' => [$header_value], 'bool' => [$report_only]));

        $directives = $this->deconstruct_header_value($header_value, 'content-security-policy');

        $csp = array();

        foreach($directives as $directive => $source_string)
        {
            $sources = explode(' ', $source_string);

            if ( ! empty($sources) and ! is_bool($source_string)) $csp[$directive] = $sources;
            else $csp[] = $directive;
        }

        $this->csp($csp, $report_only);
    }

    private function import_hsts($header_value)
    {
        $this->assert_types(array('string' => [$header_value]));

        $hsts = $this->deconstruct_header_value($header_value);

        $settings = $this->safe_mode_unsafe_headers['strict-transport-security'];

        foreach ($settings as $setting => $default)
        {
            if ( ! isset($hsts[$setting]))
            {
                $hsts[$setting] = $default;
            }
        }

        $this->hsts($hsts['max-age'], $hsts['includesubdomains'], $hsts['preload']);
    }

    private function import_hpkp($header_value, $report_only = null)
    {
        $this->assert_types(array('string' => [$header_value], 'bool' => [$report_only]));

        $hpkp = $this->deconstruct_header_value($header_value, 'public-key-pins');

        if (empty($hpkp['pin'])) return;

        $settings = $this->safe_mode_unsafe_headers['public-key-pins'];
        $settings[] = array('report-uri' => null);

        foreach ($settings as $setting => $default)
        {
            if ( ! isset($hpkp[$setting]))
            {
                $hpkp[$setting] = $default;
            }
        }

        $this->hpkp($hpkp['pin'], $hpkp['max-age'], $hpkp['includesubdomains'], $hpkp['report-uri']);
    }
    
    private function remove_headers()
    {
        foreach ($this->removed_headers as $name => $value)
        { 
            header_remove($name);
        }
    }
    
    private function send_headers()
    {
        foreach ($this->headers as $key => $header)
        {
            header($header['name'] . ($header['value'] === '' ? '' : ': ' . $header['value']));
        }

        foreach ($this->cookies as $name => $cookie)
        {
            if ( ! isset($cookie['expire']) and isset($cookie['max-age'])) $cookie['expire'] = $cookie['max-age'];

            $cookie_att = array('expire', 'path', 'domain', 'secure', 'httponly');

            foreach ($cookie_att as $att)
            {
                if ( ! isset($cookie[$att])) $cookie[$att] = null;
            }

            setcookie(
                $name,
                $cookie[0],
                $cookie['expire'],
                $cookie['path'],
                $cookie['domain'],
                $cookie['secure'],
                $cookie['httponly']
            );
        }
    }

    private function deconstruct_header_value($header = null, $name = null, $get_position = null)
    {
        $this->assert_types(array('string' => [$header, $name], 'bool' => [$get_position]));

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

        if (preg_match_all($header_re, $header, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE))
        {
            foreach ($matches as $match)
            {
                if ( ! isset($match[3][0])) $match[3][$n] = ($n ? $match[2][$n] : true);

                if ($store_multiple_values and ! empty($match[1][0]))
                {
                    $attributes[strtolower($match[1][0])][] = array($match[2][$n], $match[3][$n]);
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
            $friendly_header = preg_replace_callback(
                '/(?:^|-)([a-z])/',
                function($match){
                    return ' '.strtoupper($match[1]);
                },
                $header
            );
            if ($header === 'content-security-policy' or $header === 'content-security-policy-report-only')
            {

                if ( $header === 'content-security-policy-report-only'
                and (
                        ! isset($data['attributes']['report-uri']) 
                    or  ! preg_match('/https:\/\/[a-z0-9\-]+[.][a-z]{2,}.*/i', $data['attributes']['report-uri'])
                    )
                )
                {
                    $this->add_error($friendly_header.' header was sent, but an invalid, or no reporting '.
                        'address was given. '.
                        'This header will not enforce violations, and with no reporting address specified,'.
                        ' the browser can only report them locally in its console. '.
                        'Consider adding a reporting address to make full use of this header.'
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
                                    $friendly_header.' contains the <b>' . $bad_flag . '</b> keyword in '.
                                    '<b>' . $name .'</b>, which prevents CSP protecting against the injection of '.
                                    'arbitrary code into the page.',
                                    E_USER_WARNING
                                );
                            }
                        }
                    }

                    if (preg_match_all('/(?:[ ]|^)\K(?:https?[:](?:\/\/)?[*]?|[*])(?=[ ;]|$)/', $value, $matches))
                    {
                        $this->add_error(
                            $friendly_header.' '.(count($matches[0]) > 1 ? 
                            'contains the following wildcards ' : 'contains a wildcard ') . '<b>'.
                            implode(', ', $matches[0]).'</b> as a '. 
                            'source value in <b>'.$name.'</b>; this can allow anyone to insert '.
                            'elements covered by the <b>'.$name.'</b> directive into the page.',
                            E_USER_WARNING
                        );
                    }

                    if (preg_match_all('/(?:[ ]|^)\Khttp[:][^ ]*/', $value, $matches))
                    {
                        $this->add_error(
                            $friendly_header.' contains the insecure protocol HTTP in '.
                            (count($matches[0]) > 1 ? 'the following source values ' :  'a source value ').
                            '<b>'.implode(', ', $matches[0]).'</b>; this can allow '.
                            'anyone to insert elements covered by the <b>'.$name.'</b> directive '.
                            'into the page.',
                            E_USER_WARNING
                        );
                    }
                }
            }
        }
    }

    # ~~
    # private functions: Content-Security-Policy (CSP)

    # Content-Security-Policy: Policy string additions

    private function csp_allow($friendly_directive, $friendly_source = null, $report_only = null)
    {
        $this->assert_types(array('string' => [$friendly_directive, $friendly_source]));

        $friendly_directive = strtolower($friendly_directive);

        if (isset($this->csp_directive_shortcuts[$friendly_directive]))
        {
            $directive = $this->csp_directive_shortcuts[$friendly_directive];
        }
        else
        {
            $directive = $friendly_directive;
        }

        if (isset($this->csp_source_shortcuts[$friendly_source]))
        {
            $source = $this->csp_source_shortcuts[$friendly_source];
        }
        else
        {
            $source = $friendly_source;
        }

        $this->add_csp_source($directive, $source, $report_only);
    }

    private function add_csp_source($directive, $source = null, $report_only = null)
    {
        $this->assert_types(array('string' => [$directive, $source]));

        $csp = &$this->get_csp_object($report_only);

        if( ! isset($csp[$directive]))
        { 
            $this->add_csp_directive($directive, null, $report_only);
        }

        if($csp[$directive] === null) 
        {
            return false;
        }

        if (isset($source))
        {
            $csp[$directive][$source] = null;
        }
        else
        {
            $csp[$directive] = null;
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
                    $this->csp_allow($friendly_directive, $friendly_source, $report_only);
                }
            }
            elseif (is_int($friendly_directive) and is_string($sources))
            {
                # special case that $sources is actually a directive name, with an int index
                $friendly_directive = $sources;
                # we'll treat this case as a CSP flag
                $this->csp_allow($friendly_directive, null, $report_only);
            }
            else
            {
                if (is_array($sources) and empty($sources)) $sources = null;

                # special case that $sources isn't an array (possibly a string source, 
                # or null (or an empty array) – indicating the directive is a flag)
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
            foreach(${$type} as $directive => $sources)
            {
                $is_flag = ! isset($sources);

                $add_to_csp = "$directive".($is_flag ? '' : ' '.implode(' ', array_keys($sources))).'; ';

                if($type !== 'csp_ro' or ! in_array($directive, $this->csp_ro_blacklist))
                {
                    ${$type.'_string'} .= $add_to_csp;
                }
            }
        }

        # add CSP reporting

        if( ! empty($this->csp_reporting))
        { 
            if ( ! empty($csp_string))
            {
                $csp_string .= 'report-uri ' . $this->csp_reporting['report-uri'] . '; ';
            }

            if (
                    $this->csp_reporting['report-only-uri'] === true 
                or (empty($csp_string) and ! isset($this->csp_reporting['report-only-uri']))
            ){
                $csp_ro_string .= 'report-uri ' . $this->csp_reporting['report-uri'] . '; ';
            }
            elseif (is_string($this->csp_reporting['report-only-uri']))
            {
                $csp_ro_string .= 'report-uri ' . $this->csp_reporting['report-only-uri'] . '; ';
            }
        }

        if ( ! empty($csp_string))
        {
            $csp_string = substr($csp_string, 0, -1);

            $this->add_header('Content-Security-Policy', $csp_string);

            if($this->csp_legacy)
                $this->add_header('X-Content-Security-Policy', $csp_string);
        }
        
        if ( ! empty($csp_ro_string))
        {
            $csp_ro_string = substr($csp_ro_string, 0, -1);

            $this->add_header('Content-Security-Policy-Report-Only', $csp_ro_string);

            if($this->csp_legacy)
                $this->add_header('X-Content-Security-Policy-Report-Only', $csp_ro_string);
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

    private function add_csp_directive($name, $is_flag = null, $report_only = null)
    {
        $this->assert_types(array('string' => [$name]));

        if ( ! isset($is_flag)) $is_flag = false;

        $csp = &$this->get_csp_object($report_only);

        if(isset($csp[$name]))
        { 
            return false;
        }
        
        $csp[$name] = array();

        return true;
    }

    private function csp_do_hash($string, $algo = null, $is_file = null)
    {
        $this->assert_types(array('string' => [$string, $algo]));

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
                $this->add_error(__FUNCTION__ . ': The specified file <strong>\'' . $string . '\'</strong>, does not exist');
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
                'OpenSSL (openssl_random_pseudo_bytes) reported that it did <strong>not</strong>
                use a cryptographically strong algorithm to generate the nonce for CSP.', 
                E_USER_WARNING);
        }

        return $nonce;
    }

    # ~~
    # private functions: HSTS

    private function compile_hsts()
    {
        if ( ! empty($this->hsts))
        {
            if ( ! isset($this->hsts['max-age']))
            {
                $this->hsts['max-age'] = 31536000;
            }

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
        if ( ! empty($this->hpkp))
        {
            $hpkp_string = '';

            foreach ($this->hpkp['pins'] as list($pin, $alg))
            {
                $hpkp_string .= 'pin-' . $alg . '="' . $pin . '"; ';
            }

            if ( ! empty($hpkp_string))
            {
                if ( ! isset($this->hpkp['max-age'])) $this->hpkp['max-age'] = $this->safe_mode_unsafe_headers['public-key-pins'];

                $this->add_header(
                    'Public-Key-Pins', 
                    $hpkp_string
                        . 'max-age='.$this->hpkp['max-age'] 
                        . ($this->hpkp['includesubdomains'] ? '; includeSubDomains' :'')
                        . ($this->hpkp['report-uri'] ? '; report-uri="' .$this->hpkp['report-uri']. '"' :'')
                );
            }
        }
    }

    # ~~
    # private functions: Cookies

    private function modify_cookie($substr, $flag, $full_match = null)
    {
        $this->assert_types(array('string' => [$substr, $flag]));

        if ( ! isset($full_match)) $full_match = false;

        foreach ($this->cookies as $cookie_name => $cookie)
        {
            if (    ($full_match and $substr === strtolower($cookie_name)) 
                or  ( ! $full_match and strpos(strtolower($cookie_name), $substr) !== false)
            ){
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
            if (isset($this->safe_mode_unsafe_headers[$header]) and empty($this->safe_mode_exceptions[$header]))
            {
                $changed = false;

                foreach ($data['attributes'] as $attribute => $value)
                {
                    # if we have a safe mode preference for this attribute
                    if (isset($this->safe_mode_unsafe_headers[$header][$attribute]))
                    {
                        $default = $this->safe_mode_unsafe_headers[$header][$attribute];

                        # if the user-set value is a number, check to see if it's greater
                        # that safe mode's preference. If boolean or string check to see
                        # if the value differs 
                        if (
                            (is_bool($default) or is_string($default)) and $default !== $value
                        or  is_int($default) and intval($value) > $default
                        ){
                            # get the user-set value offset in the header value string
                            $valueOffset = $this->headers[$header]['attributePositions'][$attribute];
                            
                            # if the user-set value is a a flag, we want to replace the flag (attribute text)
                            # otherwise, we're replacing the value of the attribute
                            if (is_string($value)) $valueLength = strlen($value);
                            else $valueLength = strlen($attribute);
                            
                            # length of our default, and length diff with user-set value
                            $defaultLength = strlen($default);

                            # perform the replacement
                            $this->headers[$header]['value'] = substr_replace($this->headers[$header]['value'], $default, $valueOffset, $valueLength);

                            # in the case that a flag was removed, we may need to strip out a delimiter too
                            if ( ! is_string($value) and preg_match('/^;[ ]?/', substr($this->headers[$header]['value'], $valueOffset + $defaultLength, 2), $match))
                            {
                                $tailLength = strlen($match[0]);

                                $this->headers[$header]['value'] = substr_replace($this->headers[$header]['value'], '', $valueOffset + $defaultLength, $tailLength);
                                $defaultLength -= $tailLength;
                            }
                            
                            # make note that we changed something
                            $changed = true;

                            $lengthDiff = $defaultLength - $valueLength;

                            # correct the positions of other attributes (replace may have varied length of string)
                            foreach ($this->headers[$header]['attributePositions'] as $i => $position)
                            {
                                if ( ! is_int($position)) continue;

                                if ($position > $valueOffset)
                                {
                                    $this->headers[$header]['attributePositions'][$i] += $lengthDiff;
                                }
                            }
                        }
                    }
                }

                # if we changed something, throw a notice to let user know
                if ($changed and isset($this->safe_mode_unsafe_headers[$header][0]))
                {
                    $this->add_error($this->safe_mode_unsafe_headers[$header][0], E_USER_NOTICE);
                }
            }
        }
    }

    # ~~
    # private functions: general

    private function add_error($message, $error = E_USER_NOTICE)
    {
        $this->assert_types(array('string' => [$message], 'int' => [$error]));

        $this->errors[] = array($message, $error);
    }

    private function report_errors()
    {
        if ( ! $this->error_reporting) return;

        set_error_handler(array(get_class(), 'error_handler'));

        foreach ($this->errors as list($message, $level))
        {
            trigger_error($message, $level);
        }

        restore_error_handler();
    }

    private function preg_match_array($pattern, array $subjects, $value_capture_group = null, $pair_value_capture_group = null)
    {
        $this->assert_types(array('string' => [$pattern], 'int' => [$value_capture_group, $pair_value_capture_group]), array(1, 3, 4));

        if ( ! isset($value_capture_group)) $value_capture_group = 0;

        $matches = array();

        foreach ($subjects as $subject)
        {
            if (preg_match($pattern, $subject, $match) and isset($match[$value_capture_group]))
            {
                if ( ! isset($pair_value_capture_group)) $matches[] = $match[$value_capture_group];
                else $matches[] = array($match[$value_capture_group], $match[$pair_value_capture_group]);
            }
        }

        return $matches;
    }

    private function is_unsafe_header($name)
    {
        $this->assert_types(array('string' => [$name]));

        return ($this->safe_mode and isset($this->safe_mode_unsafe_headers[strtolower($name)]));
    }

    private function automatic_headers()
    {
        $this->propose_headers = true;

        if ($this->automatic_headers['add'])
        {
            # security headers for all (HTTP and HTTPS) connections
            $this->add_header('X-XSS-Protection', '1; mode=block', null, true);
            $this->add_header('X-Content-Type-Options', 'nosniff', null, true);
            $this->add_header('X-Frame-Options', 'Deny', null, true);
        }

        if($this->automatic_headers['remove'])
        {
            # remove headers leaking server information
            $this->remove_header('Server');
            $this->remove_header('X-Powered-By');
        }

        if($this->automatic_headers['secure-session-cookie'])
        {
            # add a secure flag to cookies that look like they hold session data
            foreach ($this->protected_cookie_identifiers['substrings'] as $substr)
            {
                $this->modify_cookie($substr, 'secure');
            }

            foreach ($this->protected_cookie_identifiers['names'] as $name)
            {
                $this->modify_cookie($name, 'secure', true);
            }
        }

        if($this->automatic_headers['safe-session-cookie'])
        {
            # add a httpOnly flag to cookies that look like they hold session data
            foreach ($this->protected_cookie_identifiers['substrings'] as $substr)
            {
                $this->modify_cookie($substr, 'httpOnly');
            }

            foreach ($this->protected_cookie_identifiers['names'] as $name)
            {
                $this->modify_cookie($name, 'httpOnly', true);
            }
        }

        $this->propose_headers = false;
    }

    private function error_handler($level, $message)
    {
        $this->assert_types(array('int' => [$level], 'string' => [$message]));

        if (error_reporting() & $level and (strtolower(ini_get('display_errors')) === 'on' and ini_get('display_errors')))
        {
            if ($level === E_USER_NOTICE)
            {
                $error = '<strong>Notice:</strong> ' . $message . "<br><br>\n\n";
            }
            elseif ($level === E_USER_WARNING)
            {
                $error = '<strong>Warning:</strong> ' . $message . "<br><br>\n\n";
            }

            if (isset($error))
            {
                echo $error;
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
            if ($type === 'bool') $type = 'boolean';
            if ($type === 'int') $type = 'integer';

            foreach ($vars as $var)
            {
                if (($var_type = gettype($var)) !== $type and $var_type !== 'NULL')
                {
                    throw new SecureHeadersTypeError('Argument '.$arg_nums[$i].' passed to '.__CLASS__."::${caller['function']}() 
                    must be of the type $type, $var_type given in ${caller['file']} on line ${caller['line']}");
                }
                $i++;
            }
        }
    }

    private function get_header_aliases($name)
    {
        $this->assert_types(array('string' => [$name]));

        if (! empty($headers = array_merge(
                    $this->preg_match_array('/^'.preg_quote($name).'$/i', array_keys($this->headers)),
                    $this->preg_match_array('/^'.preg_quote($name).'(?=[:])/i', headers_list())
                )
            )
        ){
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
                $this->add_error('Missing security header: ' . "'" . $header . "'", E_USER_WARNING);
            }
        }
    }

    # ~~
    # private variables: (non settings)

    private $headers = array();
    private $removed_headers = array();

    private $cookies = array();

    private $errors = array();

    private $csp = array();
    private $csp_ro = array();
    private $csp_reporting = array();

    private $hsts = array();
    private $hpkp = array();

    private $allow_imports = true;
    private $propose_headers = false;

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

    private $safe_mode_unsafe_headers = array(
        'strict-transport-security' => array(
            'max-age' => 86400,
            'includesubdomains' => false,
            'preload' => false,
            'HSTS settings were overridden because Safe-Mode is enabled. <a href="https://scotthelme.co.uk/death-by-copy-paste/#hstsandpreloading">
            Read about</a> some common mistakes when setting HSTS via copy/paste, and ensure you 
            <a href="https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet">
            understand the details</a> and possible side effects of this security feature before using it.'
        ),
        'public-key-pins' => array(
            'max-age' => 10,
            'includesubdomains' => false,
            'Some HPKP settings were overridden because Safe-Mode is enabled.'
        )
    );
}

class SecureHeadersTypeError extends Exception{
    public function __toString()
    {
        return  'exception ' .get_class($this). " '{$this->message}'\n"
                . "{$this->getTraceAsString()}";
    }
}
?>