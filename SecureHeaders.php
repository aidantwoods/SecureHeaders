<?php

class SecureHeaders{
    private $headers = array();
    private $removed_headers = array();

    private $errors = array();
    private $error_reporting = true;

    private $csp = array();
    private $csp_ro = array();
    private $csp_duplicate = true;
    private $csp_reporting = array();
    private $csp_ro_blacklist = array(
        'block-all-mixed-content',
        'upgrade-insecure-requests'
    );

    private $safe_mode = false;
    private $safe_mode_unsafe_headers = array(
        'Strict-Transport-Security',
        'Public-Key-Pins'
    );

    private $hsts = array();
    private $hpkp = array();
    private $allowed_hpkp_algs = array(
        'sha256'
    );

    # ~~
    # Public Functions

    # ~~
    # public functions: settings

    # safe-mode enforces settings that shouldn't cause too much accidental down-time
    # safe-mode intentionally overwrites user specified settings
    public function safe_mode($mode = null)
    {
        if ($mode === false or strtolower($mode) === 'off')
            $this->safe_mode = false;
        else
            $this->safe_mode = true;
    }

    # if operating in safe mode, use this to manually allow or prevent an overwrite
    # of a specific header
    public function allow_in_safe_mode(string $name)
    {
        if (($key = array_search($name, $this->safe_mode_unsafe_headers)) !== false)
        {
            unset($this->safe_mode_unsafe_headers[$key]);
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

        $this->headers[$name] = $value;

        unset($this->removed_headers[$name]);
    }

    public function remove_header(string $name)
    {
        if (! empty($headers = array_merge(
                    $this->preg_match_array('/^'.preg_quote($name).'/i', array_keys($this->headers)),
                    $this->preg_match_array('/^'.preg_quote($name).'(?=[:])/i', headers_list())
                )
            )
        ){
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
            'report-uri' 		=> $report_uri, 
            'report-only-uri' 	=> $report_only_uri
        );
    }

    public function remove_csp_reporting()
    {
        $this->csp_reporting = array();
    }

    public function csp_duplicate($mode)
    {
        # ($mode == true) indicates that if a report-only URI is set, but 
        # no report-only CSP has been specified the enforced CSP should be 
        # duplicated onto the report-only header.

        if ($mode == false)
            $this->csp_duplicate = false;
        else
            $this->csp_duplicate = true;
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
        $this->hsts['max-age'] 		= $max_age;
        $this->hsts['subdomains'] 	= ($subdomains == true);
        $this->hsts['preload'] 		= ($preload == true);
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
            $this->hsts['subdomains'] = false;
        else
            $this->hsts['subdomains'] = true;
    }

    # ~~
    # public functions: general

    public function done()
    {
        $this->compile_csp();
        $this->compile_hsts();
        $this->compile_hpkp();

        $this->remove_headers();

        $this->send_headers();
        $this->report_errors();
    }

    public function www_if_not_localhost()
    {
        if ($_SERVER['SERVER_NAME'] !== 'localhost' and substr($_SERVER['HTTP_HOST'], 0, 4) !== 'www.')
        {
            $this->add_header('HTTP/1.1 301 Moved Permanently');
            $this->add_header('Location', 'https://www.'.$_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI']);
        }
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
        foreach($this->removed_headers as $name => $value)
        { 
            header_remove($name);
        }
    }
    
    private function send_headers()
    {
        foreach($this->headers as $key => $value)
        {
            header($key . ($value === '' ? '' : ': ' . $value));
        }
    }
    
    private function add_security_headers()
    {
        
        
    }

    # ~~
    # private functions: Content-Security-Policy (CSP)

    private function compile_csp()
    {
        $csp_string = '';
        $csp_ro_string = '';

        $csp 	= $this->get_csp_object(false);
        $csp_ro = $this->get_csp_object(true);

        if($this->csp_duplicate and ! empty($this->csp_reporting) and empty($csp_ro))
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
            $csp_string .= 'report-uri ' . $this->csp_reporting['report-uri'] . '; ';

            if ($this->csp_reporting['report-only-uri'] === true)
            {
                $csp_ro_string .= 'report-uri ' . $this->csp_reporting['report-uri'] . '; ';
            }
            elseif (is_string($this->csp_reporting['report-only-uri']))
            {
                $csp_ro_string .= 'report-uri ' . $this->csp_reporting['report-only-uri'] . '; ';
            }

            if($this->csp_reporting['report-only-uri'] !== false)
            {
                $this->add_header('Content-Security-Policy-Report-Only', substr($csp_ro_string, 0, -1));
            }
        }

        if ( ! empty($csp_string))
            $this->add_header('Content-Security-Policy', substr($csp_string, 0, -1));
        
        if ( ! empty($csp_ro_string))
            $this->add_header('Content-Security-Policy-Report-Only', substr($csp_ro_string, 0, -1));
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
                $this->errors[] = 'HSTS settings were overridden because Safe-Mode is enabled. ' . $error_extension;
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
                $this->errors[] = 'A manually set HSTS header was removed because Safe-Mode is enabled. ' . $error_extension;
        }
    }

    # ~~
    # private functions: HSTS

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

                $this->errors[] = 'HPKP settings were overridden because Safe-Mode is enabled.';
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
                $this->errors[] = 'A manually set HPKP header was removed because Safe-Mode is enabled.';
        }
    }

    # ~~
    # private functions: general

    private function report_errors()
    {
        if ( ! $this->error_reporting) return;

        foreach ($this->errors as $error)
        {
            trigger_error($error);
        }
    }

    private function preg_match_array(string $pattern, array $subjects, int $capture_group = null)
    {
        if ( ! isset($capture_group)) $capture_group = 0;

        $matches = array();

        foreach ($subjects as $subject)
        {
            if (preg_match($pattern, $subject, $match) and isset($match[$capture_group]))
            {
                $matches[] = $match[$capture_group];
            }
        }

        return $matches;
    }

    private function is_unsafe_header($name)
    {
        return ($this->safe_mode and in_array($name, $this->safe_mode_unsafe_headers));
    }
}

class CustomSecureHeaders extends SecureHeaders{
    public function __construct()
    {
        # content headers
        $this->add_header('Content-type', 'text/html; charset=utf-8');

        # remove headers leaking server information
        $this->remove_header('Server');
        $this->remove_header('X-Powered-By');

        # security headers for all (HTTP and HTTPS) connections
        $this->add_header('X-XSS-Protection', '1; mode=block');
        $this->add_header('X-Content-Type-Options', 'nosniff');
        $this->add_header('X-Frame-Options', 'Deny');

        # redirect to www subdomain if not on localhost
        $this->www_if_not_localhost();

        # add a csp policy, as specified in $base, defined below
        $this->csp($this->base);
        $this->add_csp_reporting('https://report-uri.example.com/csp', 1);

        # add a hpkp policy
        $this->hpkp(
            array(
                'd6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=', 
                ['E9CZ9INDbd+2eRQozYqqbQ2yXLVKB9+xcprMF+44U1g=', 'sha256']
            ),
            15,
            1
        );

        # use regular PHP function to add strict transport security
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');

        # enable safe-mode, which should auto-remove the above header
        # safe-mode will generate an error of level E_USER_NOTICE if it has to remove 
        # or modify any headers
        $this->safe_mode();

        # uncomment the next line to specifically allow HSTS in safe mode
        // $this->allow_in_safe_mode('Strict-Transport-Security');

    }

    private $base = array(
        "default-src" => ["'self'"],
        "script-src" => [
            "'self'",
            "https://www.google-analytics.com/"
        ],
        "style-src" => [
            "'self'",
            "https://fonts.googleapis.com/",
            "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/"
        ],
        "img-src" => [
            "'self'",
            "https://www.google-analytics.com/",
        ],
        "font-src" => [
            "'self'",
            "https://fonts.googleapis.com/",
            "https://fonts.gstatic.com/",
            "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/"
        ],
        "child-src" => [
            "'self'"
        ],
        "frame-src" => [
            "'self'"
        ],
        "base-uri" => ["'self'"],
        "connect-src" => [
            "'self'",
            "https://www.google-analytics.com/r/collect"
        ],
        "form-action" => [
            "'self'"
        ],
        "frame-ancestors" => ["'none'"],
        "object-src" => ["'none'"],
        'block-all-mixed-content' => [null]
    );

}
?>