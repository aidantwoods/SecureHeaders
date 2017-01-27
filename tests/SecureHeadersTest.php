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

    public function testExistingHeadersAreSent()
    {
        $headerStrings = new StringHttpAdapter(array(
            'X-Foo: Bar',
        ));

        $headers = new SecureHeaders($headerStrings);
        $headers->errorReporting(false);
        $headers->done();

        $headersString = $headerStrings->getSentHeaders();

        $this->assertContains('X-Foo: Bar', $headersString);
    }

    public function testRegularHeaderNotLost()
    {
        $headerStrings = new StringHttpAdapter;

        $headers = new SecureHeaders($headerStrings);
        $headers->errorReporting(false);

        $headers->addHeader('X-Foo', 'Bar');

        $headers->done();

        $headersString = $headerStrings->getSentHeaders();

        $this->assertContains('X-Foo: Bar', $headersString);
    }

    public function testCookies()
    {
        $headerStrings = new StringHttpAdapter(array(
            'Set-Cookie: normalcookie=value1',
            'Set-Cookie: authcookie=value2',
        ));

        $headers = new SecureHeaders($headerStrings);
        $headers->errorReporting(false);

        $headers->done();

        $headersString = $headerStrings->getSentHeaders();

        $this->assertContains('Set-Cookie: normalcookie=value1', $headersString);
        $this->assertContains('Set-Cookie: authcookie=value2; Secure; HttpOnly', $headersString);
    }

    public function testMultipleHeaders()
    {
        $headerStrings = new StringHttpAdapter(array(
            'X-Bar: Foo1',
            'X-Bar: Foo2',
        ));

        $headers = new SecureHeaders($headerStrings);
        $headers->errorReporting(false);

        $headers->addHeader('X-Foo', 'Bar1', false);
        $headers->addHeader('X-Foo', 'Bar2', false);

        $headers->done();

        $headersString = $headerStrings->getSentHeaders();

        $this->assertContains('X-Foo: Bar1', $headersString);
        $this->assertContains('X-Foo: Bar2', $headersString);
        $this->assertContains('X-Bar: Foo1', $headersString);
        $this->assertContains('X-Bar: Foo2', $headersString);
    }

    public function testHeadersAreReplaced()
    {
        $headerStrings = new StringHttpAdapter;

        $headers = new SecureHeaders($headerStrings);
        $headers->errorReporting(false);

        $headers->addHeader('X-Foo', 'Bar1');
        $headers->addHeader('X-Foo', 'Bar2');

        $headers->done();

        $headersString = $headerStrings->getSentHeaders();

        $this->assertNotContains('X-Foo: Bar1', $headersString);
        $this->assertContains('X-Foo: Bar2', $headersString);
    }

    public function testThreeDefaultHeadersAreAdded()
    {
        $headerStrings = new StringHttpAdapter;

        $headers = new SecureHeaders($headerStrings);
        $headers->errorReporting(false);
        $headers->done();

        $headersString = $headerStrings->getSentHeaders();

        $this->assertContains('X-XSS-Protection: 1; mode=block', $headersString);
        $this->assertContains('X-Content-Type-Options: nosniff', $headersString);
        $this->assertContains('X-Frame-Options: Deny', $headersString);
    }

    public function testDefaultHeadersDoNotReplaceExistingHeaders()
    {
        $headerStrings = new StringHttpAdapter(array(
            'X-Frame-Options: sameorigin',
        ));

        $headers = new SecureHeaders($headerStrings);
        $headers->errorReporting(false);
        $headers->done();

        $headersString = $headerStrings->getSentHeaders();

        $this->assertContains('X-XSS-Protection: 1; mode=block', $headersString);
        $this->assertContains('X-Content-Type-Options: nosniff', $headersString);
        $this->assertContains('X-Frame-Options: sameorigin', $headersString);
        $this->assertNotContains('X-Frame-Options: Deny', $headersString);
    }

    public function testDefaultHeadersCanBeExplicitlyRemoved()
    {
        $headerStrings = new StringHttpAdapter;

        $headers = new SecureHeaders($headerStrings);
        $headers->errorReporting(false);
        $headers->removeHeader('X-XSS-Protection');
        $headers->done();

        $headersString = $headerStrings->getSentHeaders();

        $this->assertContains('X-Content-Type-Options: nosniff', $headersString);
        $this->assertContains('X-Frame-Options: Deny', $headersString);
        $this->assertNotContains('X-XSS-Protection', $headersString);
    }

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
                        'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
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
                        'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
                    'Contains' =>
                        'Strict-Transport-Security: max-age=86400'
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
                        'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
                    'Contains' =>
                        'Strict-Transport-Security: max-age=86400'
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
                        'Public-Key-Pins: max-age=10; pin-sha256="abcd"'
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

        $headersString = $headerStrings->getSentHeaders();

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
                        'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
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
                        "/Content-Security-Policy: script-src 'nonce-[^']+' 'strict-dynamic'/"
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
                        "/Content-Security-Policy: default-src 'nonce-[^']+' 'strict-dynamic'/"
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
                        "/Content-Security-Policy: default-src 'sha[^']+' 'strict-dynamic'/"
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
                        "/Content-Security-Policy: script-src 'sha[^']+' 'strict-dynamic'/"
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

        $headersString = $headerStrings->getSentHeaders();

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
