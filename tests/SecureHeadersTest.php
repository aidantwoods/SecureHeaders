<?php

namespace Aidantwoods\SecureHeaders\Tests;

use Aidantwoods\SecureHeaders\Http\StringHttpAdapter;
use Aidantwoods\SecureHeaders\SecureHeaders;
use PHPUnit_Framework_TestCase;

class SecureHeadersTest extends PHPUnit_Framework_TestCase
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

        $this->assertContains('X-Foo: Bar', $headersString);
    }

    public function testSevenDefaultHeadersAreAdded()
    {
        $headerStrings = new StringHttpAdapter;

        $headers = new SecureHeaders;
        $headers->errorReporting(false);
        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertContains('Expect-CT: max-age=0', $headersString);
        # we want to ensure ordering here, hence two header test
        $this->assertContains("Referrer-Policy: no-referrer\nReferrer-Policy: strict-origin-when-cross-origin", $headersString);
        $this->assertContains('X-Permitted-Cross-Domain-Policies: none', $headersString);
        $this->assertContains('X-XSS-Protection: 1; mode=block', $headersString);
        $this->assertContains('X-Content-Type-Options: nosniff', $headersString);
        $this->assertContains('X-Frame-Options: Deny', $headersString);
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

        $this->assertContains('Expect-CT: max-age=0', $headersString);
        # we want to ensure ordering here, hence two header test
        $this->assertContains("Referrer-Policy: no-referrer\nReferrer-Policy: strict-origin-when-cross-origin", $headersString);
        $this->assertContains('X-Permitted-Cross-Domain-Policies: none', $headersString);
        $this->assertContains('X-XSS-Protection: 1; mode=block', $headersString);
        $this->assertContains('X-Content-Type-Options: nosniff', $headersString);
        $this->assertContains('X-Frame-Options: sameorigin', $headersString);
        $this->assertNotContains('X-Frame-Options: Deny', $headersString);
    }

    public function testDefaultHeadersCanBeExplicitlyRemoved()
    {
        $headerStrings = new StringHttpAdapter;

        $headers = new SecureHeaders;
        $headers->errorReporting(false);
        $headers->removeHeader('X-XSS-Protection');
        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertContains('Expect-CT: max-age=0', $headersString);
        # we want to ensure ordering here, hence two header test
        $this->assertContains("Referrer-Policy: no-referrer\nReferrer-Policy: strict-origin-when-cross-origin", $headersString);
        $this->assertContains('X-Permitted-Cross-Domain-Policies: none', $headersString);
        $this->assertContains('X-Content-Type-Options: nosniff', $headersString);
        $this->assertContains('X-Frame-Options: Deny', $headersString);
        $this->assertNotContains('X-XSS-Protection', $headersString);
    }
}
