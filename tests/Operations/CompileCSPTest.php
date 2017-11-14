<?php

namespace Aidantwoods\SecureHeaders\Tests\Operations;

use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\SecureHeaders;
use Aidantwoods\SecureHeaders\Operations\CompileCSP;
use PHPUnit\Framework\TestCase;

class CSPTest extends TestCase
{
    public function testStrictDynamicInjectableForNonInternalPolicy()
    {
        $HeaderBag = HeaderBag::fromHeaderLines([
            "Content-Security-Policy: script-src 'nonce-abcdefg+123456'"
        ]);

        $policy = [
            'script-src' => ["'strict-dynamic'"]
        ];

        $CompileCSP = new CompileCSP($policy, []);
        $CompileCSP->modify($HeaderBag);

        $headersString = (string) $HeaderBag->get()[0];

        $this->assertSame("Content-Security-Policy: script-src 'strict-dynamic' 'nonce-abcdefg+123456'", $headersString);
    }

    public function testCSPHeaderMerge()
    {
        $HeaderBag = HeaderBag::fromHeaderLines([
            "Content-Security-Policy: default-src 'self'; script-src http://insecure.cdn.org 'self'",
            "Content-Security-Policy: block-all-mixed-content; img-src 'self' https://cdn.net"
        ]);

        $policy = [
            'script-src' => ['https://another.domain.example.com']
        ];

        $CompileCSP = new CompileCSP($policy, []);
        $CompileCSP->modify($HeaderBag);

        $headersString = (string) $HeaderBag->get()[0];

        $this->assertSame("Content-Security-Policy: script-src https://another.domain.example.com http://insecure.cdn.org 'self'; default-src 'self'; block-all-mixed-content; img-src 'self' https://cdn.net", $headersString);
    }
}
