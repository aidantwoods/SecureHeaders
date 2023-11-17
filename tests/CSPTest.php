<?php

namespace Aidantwoods\SecureHeaders\Tests;

use Aidantwoods\SecureHeaders\Http\StringHttpAdapter;
use Aidantwoods\SecureHeaders\SecureHeaders;
use PHPUnit\Framework\TestCase;

class CSPTest extends TestCase
{
    public function testStrictDynamicInjectableForNonInternalPolicy()
    {
        $headerStrings = new StringHttpAdapter([
            "Content-Security-Policy: script-src 'nonce-abcdefg+123456'",
            "Content-Security-Policy-Report-Only: script-src 'nonce-abcdefg+123456'"
        ]);

        $headers = new SecureHeaders;
        $headers->errorReporting(false);

        $headers->strictMode();

        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertStringContainsString("Content-Security-Policy: script-src 'nonce-abcdefg+123456' 'strict-dynamic'", $headersString);
        $this->assertStringContainsString("Content-Security-Policy-Report-Only: script-src 'nonce-abcdefg+123456' 'strict-dynamic'", $headersString);
    }

    public function testStrictDynamicInjectOnlyEnforced()
    {
        $headerStrings = new StringHttpAdapter([
            "Content-Security-Policy: script-src 'nonce-abcdefg+123456'",
            "Content-Security-Policy-Report-Only: script-src 'nonce-abcdefg+123456'"
        ]);

        $headers = new SecureHeaders;
        $headers->errorReporting(false);
        $headers->auto(SecureHeaders::AUTO_STRICTDYNAMIC_ENFORCE);

        $headers->strictMode();

        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertStringContainsString("Content-Security-Policy: script-src 'nonce-abcdefg+123456' 'strict-dynamic'", $headersString);
        $this->assertStringNotContainsString("Content-Security-Policy-Report-Only: script-src 'nonce-abcdefg+123456' 'strict-dynamic'", $headersString);
    }

    public function testStrictDynamicInjectOnlyReport()
    {
        $headerStrings = new StringHttpAdapter([
            "Content-Security-Policy: script-src 'nonce-abcdefg+123456'",
            "Content-Security-Policy-Report-Only: script-src 'nonce-abcdefg+123456'"
        ]);

        $headers = new SecureHeaders;
        $headers->errorReporting(false);
        $headers->auto(SecureHeaders::AUTO_STRICTDYNAMIC_REPORT);

        $headers->strictMode();

        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertStringNotContainsString("Content-Security-Policy: script-src 'nonce-abcdefg+123456' 'strict-dynamic'", $headersString);
        $this->assertStringContainsString("Content-Security-Policy-Report-Only: script-src 'nonce-abcdefg+123456' 'strict-dynamic'", $headersString);
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

                    $this->assertMatchesRegularExpression('/Content-Security-Policy:.*?'.$directive.'[^;]+'.$source.'/', $headersString);
                }
            }
            else
            {
                $this->assertMatchesRegularExpression('/Content-Security-Policy:.*?'.$directive.';/', $headersString);
            }
        }
    }
}
