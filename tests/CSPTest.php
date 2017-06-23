<?php

namespace Tests;

use Aidantwoods\SecureHeaders\Http\StringHttpAdapter;
use Aidantwoods\SecureHeaders\SecureHeaders;
use PHPUnit_Framework_TestCase;

class CSPTest extends PHPUnit_Framework_TestCase
{
    public function testStrictDynamicInjectableForNonInternalPolicy()
    {
        $headerStrings = new StringHttpAdapter([
            "Content-Security-Policy: script-src 'nonce-abcdefg+123456'"
        ]);

        $headers = new SecureHeaders;
        $headers->errorReporting(false);

        $headers->strictMode();

        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertContains("Content-Security-Policy: script-src 'nonce-abcdefg+123456' 'strict-dynamic'", $headersString);
    }

    public function testCSPHeaderMerge()
    {
        $headerStrings = new StringHttpAdapter([
            "Content-Security-Policy: default-src 'self'; script-src http://insecure.cdn.org 'self'",
            "Content-Security-Policy: block-all-mixed-content; img-src 'self' https://cdn.net"
        ]);

        $headers = new SecureHeaders;
        $headers->errorReporting(false);

        $headers->csp('script', 'https://another.domain.example.com');

        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $policy = [
            'block-all-mixed-content'
                => true,
            'img-src'
                => [
                    "'self'",
                    'https://cdn.net'
                ],
            'script-src'
                => [
                    'https://another.domain.example.com',
                    'http://insecure.cdn.org',
                    "'self'"
                ],
            'default-src'
                => ['self']
        ];

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
