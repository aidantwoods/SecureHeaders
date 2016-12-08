<?php

include('SecureHeaders.php');

class Test extends PHPUnit_Framework_TestCase
{
    private $assertions = array(
        'Contains',
        'NotContains',
        'Equals',
        'Regexp',
        'NotRegExp'
    );

    function data_safe_mode()
    {
        return array(
            array(
                'test' => 
                    function(&$headers){
                        $headers->header(
                            'Strict-Transport-Security',
                            'max-age=31536000; includeSubDomains; preload'
                        );
                    },
                'assertions' => array(
                    'Contains' =>
                        'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
                )
            ),
            array(
                'test' => 
                    function(&$headers){
                        $headers->safe_mode();
                        $headers->header(
                            'Strict-Transport-Security',
                            'max-age=31536000; includeSubDomains; preload'
                        );
                    },
                'assertions' => array(
                    'NotContains' =>
                        'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
                    'Contains' =>
                        'Strict-Transport-Security: max-age=86400'
                )
            ),
            array(
                'test' => 
                    function(&$headers){
                        $headers->safe_mode();
                        $headers->strict_mode();
                    },
                'assertions' => array(
                    'NotContains' =>
                        'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
                    'Contains' =>
                        'Strict-Transport-Security: max-age=86400'
                )
            ),
            array(
                'test' => 
                    function(&$headers){
                        $headers->safe_mode();
                        $headers->header(
                            'Public-Key-Pins',
                            'max-age=31536000; pin-sha256="abcd"; includeSubDomains'
                        );
                    },
                'assertions' => array(
                    'NotContains' =>
                        'max-age=31536000; pin-sha256="abcd"; includeSubDomains',
                    'Contains' =>
                        'Public-Key-Pins: max-age=10; pin-sha256="abcd"'
                )
            )
        );
    }

    /**
     * @dataProvider data_safe_mode
     * @param $test
     * @param $assertions
     */
    public function test_safe_mode($test, $assertions)
    {
        $headers = new SecureHeaders;
        $headers->headers_as_string(true);
        $test($headers);

        $headers_string = $headers->get_headers_as_string();

        foreach ($this->assertions as $assertion)
        {
            if (isset($assertions[$assertion]))
            {
                if ( ! is_array($assertions[$assertion]))
                {
                    $assertions[$assertion] = array($assertions[$assertion]);
                }
                foreach ($assertions[$assertion] as $assertion_string)
                {
                    $this->{'assert'.$assertion}(
                        $assertion_string,
                        $headers_string
                    );
                }
            }
        }
      }


    function data_strict_mode()
    {
        return array(
            array(
                'test' => 
                    function(&$headers){
                        $headers->strict_mode();
                    },
                'assertions' => array(
                    'Contains' =>
                        'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
                )
            ),
            array(
                'test' => 
                    function(&$headers){
                        $headers->strict_mode();
                        $headers->csp_nonce('script');
                    },
                'assertions' => array(
                    'Regexp' =>
                        "/Content-Security-Policy: script-src 'nonce-[^']+' 'strict-dynamic'/"
                )
            ),
            array(
                'test' => 
                    function(&$headers){
                        $headers->strict_mode();
                        $headers->csp_nonce('default');
                    },
                'assertions' => array(
                    'Regexp' =>
                        "/Content-Security-Policy: default-src 'nonce-[^']+' 'strict-dynamic'/"
                )
            ),
            array(
                'test' => 
                    function(&$headers){
                        $headers->strict_mode();
                        $headers->csp_nonce('default');
                        $headers->csp_nonce('script');
                    },
                'assertions' => array(
                    'Regexp' =>
                        "/script-src 'nonce-[^']+' 'strict-dynamic'/",
                    'NotRegexp' =>
                        "/default-src 'nonce-[^']+' 'strict-dynamic'/"
                )
            ),
            array(
                'test' => 
                    function(&$headers){
                        $headers->strict_mode();
                        $headers->csp_hash('default', 'abcd');
                    },
                'assertions' => array(
                    'Regexp' =>
                        "/Content-Security-Policy: default-src 'sha[^']+' 'strict-dynamic'/"
                )
            ),
            array(
                'test' => 
                    function(&$headers){
                        $headers->strict_mode();
                        $headers->csp_hash('script', 'abcd');
                    },
                'assertions' => array(
                    'Regexp' =>
                        "/Content-Security-Policy: script-src 'sha[^']+' 'strict-dynamic'/"
                )
            ),
            array(
                'test' => 
                    function(&$headers){
                        $headers->strict_mode();
                        $headers->csp_hash('default', 'abcd');
                        $headers->csp_hash('script', 'abcd');
                    },
                'assertions' => array(
                    'Regexp' =>
                        "/script-src 'sha[^']+' 'strict-dynamic'/",
                    'NotRegexp' =>
                        "/default-src 'sha[^']+' 'strict-dynamic'/"
                )
            ),
            array(
                'test' => 
                    function(&$headers){
                        $headers->strict_mode();
                        $headers->csp('default', 'http://some-cdn.org');
                        $headers->csp('script', 'http://other-cdn.net');
                    },
                'assertions' => array(
                    'NotContains' =>
                        "'strict-dynamic'"
                )
            ),
        );
    }

    /**
     * @dataProvider data_strict_mode
     * @param $test
     * @param $assertions
     */
    public function test_strict_mode($test, $assertions)
    {
        $headers = new SecureHeaders;
        $headers->headers_as_string(true);
        $test($headers);

        $headers_string = $headers->get_headers_as_string();

        foreach ($this->assertions as $assertion)
        {
            if (isset($assertions[$assertion]))
            {
                if ( ! is_array($assertions[$assertion]))
                {
                    $assertions[$assertion] = array($assertions[$assertion]);
                }
                foreach ($assertions[$assertion] as $assertion_string)
                {
                    $this->{'assert'.$assertion}(
                        $assertion_string,
                        $headers_string
                    );
                }
            }
        }
      }
}   
?>