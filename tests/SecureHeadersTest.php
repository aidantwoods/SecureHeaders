<?php

namespace Tests;

use Aidantwoods\SecureHeaders\Http\StringHttpAdapter;
use Aidantwoods\SecureHeaders\SecureHeaders;
use PHPUnit_Framework_TestCase;

class SecureHeadersTest extends PHPUnit_Framework_TestCase
{
    private $assertions = array(
        'Contains',
        'NotContains',
        'Equals',
        'Regexp',
        'NotRegExp'
    );

    function dataSafeMode()
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
                        'strict-transport-security: max-age=31536000; includeSubDomains; preload'
                )
            ),
            array(
                'test' => 
                    function(&$headers){
                        $headers->safeMode();
                        $headers->header(
                            'Strict-Transport-Security',
                            'max-age=31536000; includeSubDomains; preload'
                        );
                    },
                'assertions' => array(
                    'NotContains' =>
                        'strict-transport-security: max-age=31536000; includeSubDomains; preload',
                    'Contains' =>
                        'strict-transport-security: max-age=86400'
                )
            ),
            array(
                'test' => 
                    function(&$headers){
                        $headers->safeMode();
                        $headers->strictMode();
                    },
                'assertions' => array(
                    'NotContains' =>
                        'strict-transport-security: max-age=31536000; includeSubDomains; preload',
                    'Contains' =>
                        'strict-transport-security: max-age=86400'
                )
            ),
            array(
                'test' => 
                    function(&$headers){
                        $headers->safeMode();
                        $headers->header(
                            'Public-Key-Pins',
                            'max-age=31536000; pin-sha256="abcd"; includeSubDomains'
                        );
                    },
                'assertions' => array(
                    'NotContains' =>
                        'max-age=31536000; pin-sha256="abcd"; includeSubDomains',
                    'Contains' =>
                        'public-key-pins: max-age=10; pin-sha256="abcd"'
                )
            )
        );
    }

    /**
     * @dataProvider dataSafeMode
     * @param $test
     * @param $assertions
     */
    public function testSafeMode($test, $assertions)
    {
        $headers = new SecureHeaders($headerStrings = new StringHttpAdapter);
        $headers->errorReporting(false);
        $test($headers);
        $headers->done();

        $headersString = $headerStrings->getHeadersAsString();

        foreach ($this->assertions as $assertion)
        {
            if (isset($assertions[$assertion]))
            {
                if ( ! is_array($assertions[$assertion]))
                {
                    $assertions[$assertion] = array($assertions[$assertion]);
                }
                foreach ($assertions[$assertion] as $assertionString)
                {
                    $this->{'assert'.$assertion}(
                        $assertionString,
                        $headersString
                    );
                }
            }
        }
      }


    function dataStrictMode()
    {
        return array(
            array(
                'test' => 
                    function(&$headers){
                        $headers->strictMode();
                    },
                'assertions' => array(
                    'Contains' =>
                        'strict-transport-security: max-age=31536000; includeSubDomains; preload'
                )
            ),
            array(
                'test' => 
                    function(&$headers){
                        $headers->strictMode();
                        $headers->cspNonce('script');
                    },
                'assertions' => array(
                    'Regexp' =>
                        "/content-security-policy: script-src 'nonce-[^']+' 'strict-dynamic'/"
                )
            ),
            array(
                'test' => 
                    function(&$headers){
                        $headers->strictMode();
                        $headers->cspNonce('default');
                    },
                'assertions' => array(
                    'Regexp' =>
                        "/content-security-policy: default-src 'nonce-[^']+' 'strict-dynamic'/"
                )
            ),
            array(
                'test' => 
                    function(&$headers){
                        $headers->strictMode();
                        $headers->cspNonce('default');
                        $headers->cspNonce('script');
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
                        $headers->strictMode();
                        $headers->cspHash('default', 'abcd');
                    },
                'assertions' => array(
                    'Regexp' =>
                        "/content-security-policy: default-src 'sha[^']+' 'strict-dynamic'/"
                )
            ),
            array(
                'test' => 
                    function(&$headers){
                        $headers->strictMode();
                        $headers->cspHash('script', 'abcd');
                    },
                'assertions' => array(
                    'Regexp' =>
                        "/content-security-policy: script-src 'sha[^']+' 'strict-dynamic'/"
                )
            ),
            array(
                'test' => 
                    function(&$headers){
                        $headers->strictMode();
                        $headers->cspHash('default', 'abcd');
                        $headers->cspHash('script', 'abcd');
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
                        $headers->strictMode();
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
     * @dataProvider dataStrictMode
     * @param $test
     * @param $assertions
     */
    public function testStrictMode($test, $assertions)
    {
        $headers = new SecureHeaders($headerStrings = new StringHttpAdapter);
        $headers->errorReporting(false);
        $test($headers);
        $headers->done();

        $headersString = $headerStrings->getHeadersAsString();

        foreach ($this->assertions as $assertion)
        {
            if (isset($assertions[$assertion]))
            {
                if ( ! is_array($assertions[$assertion]))
                {
                    $assertions[$assertion] = array($assertions[$assertion]);
                }
                foreach ($assertions[$assertion] as $assertionString)
                {
                    $this->{'assert'.$assertion}(
                        $assertionString,
                        $headersString
                    );
                }
            }
        }
      }
}   
