<?php

class SecureHeaders{
    # ~~
    # private variables: settings

    private $error_reporting = true;
 
    private $csp_duplicate = true;
    private $csp_ro_blacklist = array(
        'block-all-mixed-content',
        'upgrade-insecure-requests'
    );

    private $csp_legacy = false;

    private $safe_mode = false;
    private $safe_mode_unsafe_headers = array(
        'Strict-Transport-Security',
        'Public-Key-Pins'
    );

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
        // 'Public-Key-Pins',
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

    public function allow_in_safe_mode(string $name)
    {
        if (($key = array_search($name, $this->safe_mode_unsafe_headers)) !== false)
        {
            unset($this->safe_mode_unsafe_headers[$key]);
        }
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

    public function add_protected_cookie_name(string $name)
    {
        if ( ! in_array(strtolower($name), $this->protected_cookie_identifiers['names']))
        {
            $this->protected_cookie_identifiers['names'][] = strtolower($name);
        }
    }

    public function remove_protected_cookie_name(string $name)
    {
        if (($key = array_search(strtolower($name), $this->protected_cookie_identifiers['names'])) !== false)
        {
            unset($this->protected_cookie_identifiers['names'][$key]);
        }
    }

    public function add_protected_cookie_substring(string $substr)
    {
        if ( ! in_array(strtolower($substr), $this->protected_cookie_identifiers['substrings']))
        {
            $this->protected_cookie_identifiers['substrings'][] = strtolower($substr);
        }
    }

    public function remove_protected_cookie_substring(string $substr)
    {
        if (($key = array_search(strtolower($substr), $this->protected_cookie_identifiers['substrings'])) !== false)
        {
            unset($this->protected_cookie_identifiers['substrings'][$key]);
        }
    }

    # ~~
    # public functions: raw headers

    public function add_header(
        string $name, string $value = null, boolean $attempt_name_correction = null, $proposal = null
    ){
        if (isset($proposal) and $proposal and isset($this->removed_headers[strtolower($name)]))
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

        # if its actually a cookie, PHP can't send more than
        # one header by the same name, unless sending a cookie
        # but this requires special handling

        $capitalised_name = $name;

        $name = strtolower($name);

        if ($name === 'set-cookie')
        {
            $this->add_cookie($value, null, true);
        }
        else
        {
            $this->headers[$name] = array(
                'name' => $capitalised_name,
                'value' => $value,
                'attributes' => $this->deconstruct_header_value($value, $name)
            );

            unset($this->removed_headers[$name]);
        }
    }

    public function remove_header(string $name)
    {
        if (! empty($headers = $this->get_header_aliases($name)))
        {
            foreach ($headers as $header)
            {
                unset($this->headers[$header]);
            }

            return true;
        }

        $this->removed_headers[strtolower($name)] = true;

        return false;
    }

    # ~~
    # public functions: cookies

    public function add_cookie(string $name, string $value = null, $extract_cookie = null)
    {
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

    public function remove_cookie(string $name)
    {
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

     # Content-Security-Policy: Reporting

    public function add_csp_reporting(string $report_uri, $report_only_uri = null)
    {
        if (isset($report_only_uri) and ! is_string($report_only_uri))
        {
            $report_only_uri = ($report_only_uri == true);
        }
        elseif ( ! isset($report_only_uri)) $report_only_uri = false;

        $this->csp_reporting = array(
            'report-uri'        => $report_uri, 
            'report-only-uri'   => $report_only_uri
        );
    }

    public function remove_csp_reporting()
    {
        $this->csp_reporting = array();
    }

     # Content-Security-Policy: Settings

    public function csp_duplicate($mode)
    {
        /** 
         * ($mode == true) indicates that if a report-only URI is set, but 
         * no report-only CSP has been specified the enforced CSP should be 
         * duplicated onto the report-only header.
         */

        if ($mode == false)
            $this->csp_duplicate = false;
        else
            $this->csp_duplicate = true;
    }

    public function add_csp_legacy()
    {
        $this->csp_legacy = true;
    }

    public function remove_csp_legacy()
    {
        $this->csp_legacy = false;
    }

    # Content-Security-Policy: Policy string removals

    public function remove_csp_source(string $directive, string $source, $report_only = null)
    {
        $csp = &$this->get_csp_object($report_only);

        if( ! isset($csp[$directive]))
        {
            return false;
        }
        
        unset($csp[$directive][$source]);

        return true;
    }

    public function remove_csp_directive(string $directive, $report_only = null)
    {
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

    public function csp_hash(string $friendly_directive, string $string, string $algo = null, $is_file = null, $report_only = null)
    {
        if ( ! isset($algo)) $algo = 'sha256';

        $hash = $this->csp_do_hash($string, $algo, $is_file);

        $hash_string = "'$algo-" . $hash ."'";

        $this->csp_allow($friendly_directive, $hash_string, $report_only);

        return $hash;
    }

    public function cspro_hash(string $friendly_directive, string $string, string $algo = null, $is_file = null)
    {
        return $this->csp_hash($friendly_directive, $string, $algo, $is_file, true);
    }

    public function csp_hash_file(string $friendly_directive, string $string, string $algo = null, $report_only = null)
    {
        return $this->csp_hash($friendly_directive, $string, $algo, true, $report_only);
    }

    public function cspro_hash_file(string $friendly_directive, string $string, string $algo = null)
    {
        return $this->csp_hash($friendly_directive, $string, $algo, true, true);
    }
 
    # Content-Security-Policy: Nonce

    public function csp_nonce(string $friendly_directive, $report_only = null)
    {
        $nonce = $this->csp_generate_nonce();

        $nonce_string = "'nonce-$nonce'";

        $this->csp_allow($friendly_directive, $nonce_string,$report_only);

        return $nonce;
    }

    public function cspro_nonce(string $friendly_directive)
    {
        return $this->csp_nonce($friendly_directive, true);
    }

    # ~~
    # public functions: HSTS

    public function hsts(int $max_age = null, $subdomains = false, $preload = false)
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

    public function hpkp(array $pins, int $max_age = null, $subdomains = null)
    {
        if(isset($max_age) or ! isset($this->hpkp['max-age'])) 
            $this->hpkp['max-age'] 	= $max_age;

        if(isset($subdomains) or ! isset($this->hpkp['subdomains'])) 
            $this->hpkp['subdomains'] = (isset($subdomains) ? ($subdomains == true) : null);

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
            $this->hpkp['subdomains'] = false;
        else
            $this->hpkp['subdomains'] = true;
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

    private function deconstruct_header_value(string $header = null, string $name = null)
    {
        if ( ! isset($header)) return array();

        $attributes = array();
        
        if (isset($name) and strpos($name, 'content-security-policy') !== false)
        {
            $header_re = '/[; ]*([^; ]+)(?:(?:[ ])([^;]+)|)/';
        }
        else
        {
            $header_re = '/[; ]*([^;=]+)(?:(?:=)([^;]+)|)/';
        }

        if (preg_match_all($header_re, $header, $matches, PREG_SET_ORDER))
        {
            foreach ($matches as $match)
            {
                if ( ! isset($match[2])) $match[2] = true;

                # don't overwrite an existing entry
                if ( ! isset($attributes[strtolower($match[1])]))
                { 
                    $attributes[strtolower($match[1])] = $match[2];
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

    private function csp_allow(string $friendly_directive, string $friendly_source = null, $report_only = null)
    {
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

    private function add_csp_source(string $directive, string $source = null, $report_only = null)
    {
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

        if($this->csp_duplicate and isset($this->csp_reporting['report-only-uri']) and empty($csp_ro))
        {
            $csp_ro = $csp;
        }

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

    private function add_csp_directive(string $name, $is_flag = null, $report_only = null)
    {
        if ( ! isset($is_flag)) $is_flag = false;

        $csp = &$this->get_csp_object($report_only);

        if(isset($csp[$name]))
        { 
            return false;
        }
        
        $csp[$name] = array();

        return true;
    }

    private function csp_do_hash(string $string, string $algo = null, $is_file = null)
    {
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
        $error_extension = '<a href="https://scotthelme.co.uk/death-by-copy-paste/#hstsandpreloading">
        Read about</a> some common mistakes when setting HSTS via copy/paste, and ensure you 
        <a href="https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet">
        understand the details</a> and possible side effects of this security feature before using it.';

        $safe_mode_max_age = 86400; # 1 day

        if ( ! empty($this->hsts))
        {
            if ( ! isset($this->hsts['max-age']))
            {
                $this->hsts['max-age'] = 31536000;
            }

            if ($this->is_unsafe_header('Strict-Transport-Security'))
            {
                if ($this->hsts['max-age'] > $safe_mode_max_age) $this->hsts['max-age'] = $safe_mode_max_age;
                // $this->hsts['subdomains'] 	= false;
                $this->hsts['preload'] 		= false;
                $this->add_error('HSTS settings were overridden because Safe-Mode is enabled. ' . $error_extension);
            }

            $this->add_header(
                'Strict-Transport-Security', 
                'max-age='.$this->hsts['max-age'] 
                    . ($this->hsts['subdomains'] ? '; includeSubDomains' :'') 
                    . ($this->hsts['preload'] ? '; preload' :'')
            );
        }
        elseif ($this->is_unsafe_header('Strict-Transport-Security'))
        {
            if ($this->remove_header('Strict-Transport-Security'))
                $this->add_error('A manually set HSTS header was removed because Safe-Mode is enabled. ' . $error_extension);
        }
    }

    # ~~
    # private functions: HPKP

    private function compile_hpkp()
    {
        if ( ! empty($this->hpkp))
        {
            if ( ! isset($this->hpkp['max-age']))
            {
                $this->hpkp['max-age'] = 10;
            }

            if ($this->is_unsafe_header('Public-Key-Pins'))
            {
                $this->hpkp['max-age'] 		= 10;
                $this->hpkp['subdomains'] 	= false;

                $this->add_error('HPKP settings were overridden because Safe-Mode is enabled.');
            }

            $hpkp_string = '';

            foreach ($this->hpkp['pins'] as list($pin, $alg))
            {
                $hpkp_string .= 'pin-' . $alg . '="' . $pin . '"; ';
            }

            if ( ! empty($hpkp_string))
            {
                if ( ! isset($this->hpkp['max-age'])) $this->hpkp['max-age'] = 10;

                $this->add_header(
                    'Public-Key-Pins', 
                    $hpkp_string
                        . 'max-age='.$this->hpkp['max-age'] 
                        . ($this->hpkp['subdomains'] ? '; includeSubDomains' :'')
                );
            }
        }
        elseif ($this->is_unsafe_header('Public-Key-Pins'))
        {
            if ($this->remove_header('Public-Key-Pins'))
                $this->add_error('A manually set HPKP header was removed because Safe-Mode is enabled.');
        }
    }

    # ~~
    # private functions: Cookies

    private function modify_cookie(string $substr, string $flag, $full_match = null)
    {
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
    # private functions: general

    private function add_error(string $message, int $error = E_USER_NOTICE)
    {
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

    private function preg_match_array(string $pattern, array $subjects, int $value_capture_group = null, int $pair_value_capture_group = null)
    {
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
        return ($this->safe_mode and in_array($name, $this->safe_mode_unsafe_headers));
    }

    private function automatic_headers()
    {
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
    }

    private static function error_handler($level, $message)
    {
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

    private function get_header_aliases(string $name)
    {
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
            if (empty($this->get_header_aliases($header)))
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
}
?>