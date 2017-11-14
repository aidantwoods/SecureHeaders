<?php

namespace Aidantwoods\SecureHeaders\Tests\Headers;

use Aidantwoods\SecureHeaders\Headers\CSPHeader;
use PHPUnit\Framework\TestCase;

class CSPHeaderTest extends TestCase
{
    public function testInjectFlag()
    {
        $Header = new CSPHeader(
            'Content-Security-Policy',
            'default-src https://example.com'
        );

        $Header->setAttribute('upgrade-insecure-requests');

        $this->assertSame(
            'Content-Security-Policy: '
            . 'default-src https://example.com; '
            . 'upgrade-insecure-requests',

            (string) $Header
        );
    }

    public function testInjectDirectivesAndSources()
    {
        $Header = new CSPHeader(
            'Content-Security-Policy',
            'default-src https://example.com'
        );

        $Header->setAttribute('script-src', 'https://example.com');
        $Header->setAttribute('script-src', 'https://foo.example.com');
        $Header->setAttribute('style-src', 'https://bar.example.com');
        $Header->setAttribute('default-src', 'https://baz.example.com');

        $this->assertSame(
            'Content-Security-Policy: '
            . 'default-src https://example.com https://baz.example.com; '
            . 'script-src https://example.com https://foo.example.com; '
            . 'style-src https://bar.example.com',

            (string) $Header
        );
    }

    public function testDuplicateSourceIgnored()
    {
        $Header = new CSPHeader(
            'Content-Security-Policy',
            'default-src https://example.com'
        );

        $Header->setAttribute('default-src', 'https://example.com');

        $this->assertSame(
            'Content-Security-Policy: default-src https://example.com',
            (string) $Header
        );
    }
}
