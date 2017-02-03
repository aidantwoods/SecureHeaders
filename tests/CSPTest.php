<?php

namespace Tests;

use Aidantwoods\SecureHeaders\Http\StringHttpAdapter;
use Aidantwoods\SecureHeaders\SecureHeaders;
use PHPUnit_Framework_TestCase;

class CSPTest extends PHPUnit_Framework_TestCase
{
    public function testStrictDynamicInjectableForNonInternalPolicy()
    {
        $headerStrings = new StringHttpAdapter(array(
            "Content-Security-Policy: script-src 'nonce-abcdefg+123456'"
        ));

        $headers = new SecureHeaders($headerStrings);
        $headers->errorReporting(false);

        $headers->strictMode();

        $headers->done();

        $headersString = $headerStrings->getSentHeaders();

        $this->assertContains("Content-Security-Policy: script-src 'nonce-abcdefg+123456' 'strict-dynamic'", $headersString);
    }

    public function testCSPHeaderMerge()
    {
        $headerStrings = new StringHttpAdapter(array(
            "Content-Security-Policy: default-src 'self'; script-src http://insecure.cdn.org 'self'",
            "Content-Security-Policy: block-all-mixed-content; img-src 'self' https://cdn.net"
        ));

        $headers = new SecureHeaders($headerStrings);
        $headers->errorReporting(false);

        $headers->csp('script', 'https://another.domain.example.com');

        $headers->done();

        $headersString = $headerStrings->getSentHeaders();

        $policy = array(
            'block-all-mixed-content' 
                => true,
            'img-src'
                => array(
                    "'self'",
                    'https://cdn.net'
                ),
            'script-src'
                => array(
                    'https://another.domain.example.com',
                    'http://insecure.cdn.org',
                    "'self'"
                ),
            'default-src'
                => array('self')
        );

        $this->assertEquivalentCSP($policy, $headersString);
    }

    public function assertEquivalentCSP($policy, $headersString)
    {
        foreach ($policy as $directive => $sources)
        {
            $directive = preg_quote($directive, '/');

            if ($sources !== true)
            {
                foreach ($sources as $source)
                {
                    $source = preg_quote($source, '/');

                    $this->assertRegexp('/Content-Security-Policy:.*?'.$directive.'[^;]+'.$source.'/', $headersString);
                }
            }
            else
            {
                $this->assertRegexp('/Content-Security-Policy:.*?'.$directive.';/', $headersString);
            }
        }
    }
}   
