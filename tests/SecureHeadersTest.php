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

    public function testFourDefaultHeadersAreAdded()
    {
        $headerStrings = new StringHttpAdapter;

        $headers = new SecureHeaders($headerStrings);
        $headers->errorReporting(false);
        $headers->done();

        $headersString = $headerStrings->getSentHeaders();

        $this->assertContains('X-Permitted-Cross-Domain-Policies: none', $headersString);
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

        $this->assertContains('X-Permitted-Cross-Domain-Policies: none', $headersString);
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

        $this->assertContains('X-Permitted-Cross-Domain-Policies: none', $headersString);
        $this->assertContains('X-Content-Type-Options: nosniff', $headersString);
        $this->assertContains('X-Frame-Options: Deny', $headersString);
        $this->assertNotContains('X-XSS-Protection', $headersString);
    }
}   
