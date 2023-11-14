<?php

namespace Aidantwoods\SecureHeaders\Tests;

use Aidantwoods\SecureHeaders\Http\StringHttpAdapter;
use Aidantwoods\SecureHeaders\SecureHeaders;
use PHPUnit\Framework\TestCase;

class SecureHeadersTest extends TestCase
{
    private $assertions = [
        'Contains',
        'NotContains',
        'Equals',
        'Regexp',
        'NotRegExp'
    ];

    public function testExistingHeadersAreSent()
    {
        $headerStrings = new StringHttpAdapter([
            'X-Foo: Bar',
        ]);

        $headers = new SecureHeaders;
        $headers->errorReporting(false);
        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertStringContainsString('X-Foo: Bar', $headersString);
    }

    public function testSevenDefaultHeadersAreAdded()
    {
        $headerStrings = new StringHttpAdapter;

        $headers = new SecureHeaders;
        $headers->errorReporting(false);
        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertStringContainsString('Expect-CT: max-age=0', $headersString);
        # we want to ensure ordering here, hence two header test
        $this->assertStringContainsString("Referrer-Policy: no-referrer\nReferrer-Policy: strict-origin-when-cross-origin", $headersString);
        $this->assertStringContainsString('X-Permitted-Cross-Domain-Policies: none', $headersString);
        $this->assertStringContainsString('X-XSS-Protection: 1; mode=block', $headersString);
        $this->assertStringContainsString('X-Content-Type-Options: nosniff', $headersString);
        $this->assertStringContainsString('X-Frame-Options: Deny', $headersString);
    }

    public function testDefaultHeadersDoNotReplaceExistingHeaders()
    {
        $headerStrings = new StringHttpAdapter([
            'X-Frame-Options: sameorigin',
        ]);

        $headers = new SecureHeaders;
        $headers->errorReporting(false);
        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertStringContainsString('Expect-CT: max-age=0', $headersString);
        # we want to ensure ordering here, hence two header test
        $this->assertStringContainsString("Referrer-Policy: no-referrer\nReferrer-Policy: strict-origin-when-cross-origin", $headersString);
        $this->assertStringContainsString('X-Permitted-Cross-Domain-Policies: none', $headersString);
        $this->assertStringContainsString('X-XSS-Protection: 1; mode=block', $headersString);
        $this->assertStringContainsString('X-Content-Type-Options: nosniff', $headersString);
        $this->assertStringContainsString('X-Frame-Options: sameorigin', $headersString);
        $this->assertStringNotContainsString('X-Frame-Options: Deny', $headersString);
    }

    public function testDefaultHeadersCanBeExplicitlyRemoved()
    {
        $headerStrings = new StringHttpAdapter;

        $headers = new SecureHeaders;
        $headers->errorReporting(false);
        $headers->removeHeader('X-XSS-Protection');
        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertStringContainsString('Expect-CT: max-age=0', $headersString);
        # we want to ensure ordering here, hence two header test
        $this->assertStringContainsString("Referrer-Policy: no-referrer\nReferrer-Policy: strict-origin-when-cross-origin", $headersString);
        $this->assertStringContainsString('X-Permitted-Cross-Domain-Policies: none', $headersString);
        $this->assertStringContainsString('X-Content-Type-Options: nosniff', $headersString);
        $this->assertStringContainsString('X-Frame-Options: Deny', $headersString);
        $this->assertStringNotContainsString('X-XSS-Protection', $headersString);
    }
}
