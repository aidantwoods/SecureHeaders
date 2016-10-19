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

    private $protected_cookie_substrings = array(
        'sess',
        'auth',
        'login'
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

    /**
     * if operating in safe mode, use this to manually allow or prevent an overwrite
     * of a specific header
     */
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

    public function add_protected_cookie_substring(string $substr)
    {
        if ( ! in_array($substr, $this->protected_cookie_substrings))
        {
            $this->protected_cookie_substrings[] = strtolower($substr);
        }
    }

    public function remove_protected_cookie_substring(string $substr)
    {
        if (($key = array_search($substr, $this->protected_cookie_substrings)) !== false)
        {
            unset($this->protected_cookie_substrings[$key]);
        }
    }

    # ~~
    # public functions: raw headers

    public function add_header(
        string $name, string $value = null, boolean $attempt_name_correction = null
    ){
        if ( ! isset($attempt_name_correction)) $attempt_name_correction = true;

        if ( ! isset($auto_caps)) $auto_caps = true;

        if ($attempt_name_correction and preg_match('/([^:]+)/', $name, $match))
        {
            $name = $match[1];
        }

        # if its actually a cookie, PHP can't send more than
        # one header by the same name, unless sending a cookie
        # but this requires special handling

        if (strtolower($name) === 'set-cookie')
        {
            $this->add_cookie($value);
        }
        else
        {
            $this->headers[$name] = $value;

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

                $this->removed_headers[$header] = null;
            }

            return true;
        }

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

    public function csp(array $csp, $report_only = false)
    {
        foreach ($csp as $directive => $sources)
        {
            foreach ($sources as $source)
            {
                $this->add_csp_source($directive, $source, $report_only);
            }
        }
    }

    public function csp_report_only(array $csp)
    {
        $this->csp($csp, true);
    }

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

    public function add_csp_source(string $directive, string $source = null, $report_only = null)
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
        $this->import_cookies();
        $this->automatic_headers();

        $this->compile_csp();
        $this->compile_hsts();
        $this->compile_hpkp();

        $this->remove_headers();

        $this->send_headers();

        $this->report_missing_headers();
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
    
    private function remove_headers()
    {
        foreach ($this->removed_headers as $name => $value)
        { 
            header_remove($name);
        }
    }
    
    private function send_headers()
    {
        foreach ($this->headers as $key => $value)
        {
            header($key . ($value === '' ? '' : ': ' . $value));
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

    # ~~
    # private functions: Content-Security-Policy (CSP)

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

    # ~~
    # private functions: HSTS

    private function compile_hsts()
    {
        $error_extension = '<a href="https://scotthelme.co.uk/death-by-copy-paste/#hstsandpreloading">Read about</a> some common mistakes when setting HSTS via copy/paste, and ensure you <a href="https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet">understand the details</a> and possible side effects of this security feature before using it.';

        if ( ! empty($this->hsts))
        {
            if ( ! isset($this->hsts['max-age']))
            {
                $this->hsts['max-age'] = 31536000;
            }

            if ($this->is_unsafe_header('Strict-Transport-Security'))
            {
                $this->hsts['max-age'] 		= 86400;
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

    private function import_cookies()
    {
        # first grab any cookies out of already set PHP headers_list

        $set_cookies = $this->preg_match_array('/^(set-cookie)[:][ ](.*)$/i', headers_list(), 1, 2);
        header_remove('set-cookie');

        # if any, add these to our internal cookie list
        foreach ($set_cookies as $set_cookie)
        {
            $this->add_cookie($set_cookie[1], null, 1);
        }
    }

    private function modify_cookie(string $substr, string $flag)
    {
        foreach ($this->cookies as $cookie_name => $cookie)
        {
            if (strpos(strtolower($cookie_name), $substr) !== false)
            {
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
            $this->add_header('X-XSS-Protection', '1; mode=block');
            $this->add_header('X-Content-Type-Options', 'nosniff');
            $this->add_header('X-Frame-Options', 'Deny');
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
            foreach ($this->protected_cookie_substrings as $substr)
            {
                $this->modify_cookie($substr, 'secure');
            }
        }

        if($this->automatic_headers['safe-session-cookie'])
        {
            # add a httpOnly flag to cookies that look like they hold session data
            foreach ($this->protected_cookie_substrings as $substr)
            {
                $this->modify_cookie($substr, 'httpOnly');
            }
        }
    }

    private static function error_handler($level, $message)
    {
        if (error_reporting() & $level)
        {
            if ($level === E_USER_NOTICE)
            {
                echo '<strong>Notice:</strong> ' . $message . "<br><br>\n\n";
                return true;
            }
            elseif ($level === E_USER_WARNING)
            {
                echo '<strong>Warning:</strong> ' . $message . "<br><br>\n\n";
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
}
?>