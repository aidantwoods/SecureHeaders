<?php

namespace Aidantwoods\SecureHeaders\Tests\Operations;

use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Operations\InjectStrictDynamic;
use PHPUnit\Framework\TestCase;

class InjectStrictDynamicTest extends TestCase
{
    private $algs = ['sha256', 'sha384', 'sha512'];

    public function testSDInjectedInDefaultSrc()
    {
        $HeaderBag = HeaderBag::fromHeaderLines([
            "Content-Security-Policy: default-src 'nonce-1234'",
        ]);

        $InjSD = new InjectStrictDynamic($this->algs, InjectStrictDynamic::ENFORCE | InjectStrictDynamic::REPORT);
        $InjSD->modify($HeaderBag);

        $this->assertCount(1, $HeaderBag->get());

        $headerString = (string) $HeaderBag->get()[0];

        $this->assertSame("Content-Security-Policy: default-src 'nonce-1234' 'strict-dynamic'", $headerString);
    }

    public function testSDInjectedInHashDefaultSrc()
    {
        $HeaderBag = HeaderBag::fromHeaderLines([
            "Content-Security-Policy: default-src 'sha256-1234'",
        ]);

        $InjSD = new InjectStrictDynamic($this->algs, InjectStrictDynamic::ENFORCE | InjectStrictDynamic::REPORT);
        $InjSD->modify($HeaderBag);

        $this->assertCount(1, $HeaderBag->get());

        $headerString = (string) $HeaderBag->get()[0];

        $this->assertSame("Content-Security-Policy: default-src 'sha256-1234' 'strict-dynamic'", $headerString);
    }

    public function testSDInjectedInNonceScriptSrc()
    {
        $HeaderBag = HeaderBag::fromHeaderLines([
            "Content-Security-Policy: script-src 'nonce-1234'",
        ]);

        $InjSD = new InjectStrictDynamic($this->algs, InjectStrictDynamic::ENFORCE | InjectStrictDynamic::REPORT);
        $InjSD->modify($HeaderBag);

        $this->assertCount(1, $HeaderBag->get());

        $headerString = (string) $HeaderBag->get()[0];

        $this->assertSame("Content-Security-Policy: script-src 'nonce-1234' 'strict-dynamic'", $headerString);
    }

    public function testSDInjectedInHashScriptSrc()
    {
        $HeaderBag = HeaderBag::fromHeaderLines([
            "Content-Security-Policy: script-src 'sha256-1234'",
        ]);

        $InjSD = new InjectStrictDynamic($this->algs, InjectStrictDynamic::ENFORCE | InjectStrictDynamic::REPORT);
        $InjSD->modify($HeaderBag);

        $this->assertCount(1, $HeaderBag->get());

        $headerString = (string) $HeaderBag->get()[0];

        $this->assertSame("Content-Security-Policy: script-src 'sha256-1234' 'strict-dynamic'", $headerString);
    }

    public function testSDInjectedInScriptSrcWhenDefaultSrcPresent()
    {
        $HeaderBag = HeaderBag::fromHeaderLines([
            "Content-Security-Policy: default-src 'nonce-1234'; script-src 'nonce-abcd'",
        ]);

        $InjSD = new InjectStrictDynamic($this->algs, InjectStrictDynamic::ENFORCE | InjectStrictDynamic::REPORT);
        $InjSD->modify($HeaderBag);

        $this->assertCount(1, $HeaderBag->get());

        $headerString = (string) $HeaderBag->get()[0];

        $this->assertSame("Content-Security-Policy: default-src 'nonce-1234'; script-src 'nonce-abcd' 'strict-dynamic'", $headerString);
    }

    public function testSDNotInjectedWhenScriptSrcHasNonNonce()
    {
        $HeaderBag = HeaderBag::fromHeaderLines([
            "Content-Security-Policy: default-src 'nonce-1234'; script-src http://example.com",
        ]);

        $InjSD = new InjectStrictDynamic($this->algs, InjectStrictDynamic::ENFORCE | InjectStrictDynamic::REPORT);
        $InjSD->modify($HeaderBag);

        $this->assertCount(1, $HeaderBag->get());

        $headerString = (string) $HeaderBag->get()[0];

        $this->assertSame("Content-Security-Policy: default-src 'nonce-1234'; script-src http://example.com", $headerString);
    }

    public function testSDInjectedInCSPRO()
    {
        $HeaderBag = HeaderBag::fromHeaderLines([
            "Content-Security-Policy-Report-Only: default-src 'nonce-1234'",
        ]);

        $InjSD = new InjectStrictDynamic($this->algs, InjectStrictDynamic::ENFORCE | InjectStrictDynamic::REPORT);
        $InjSD->modify($HeaderBag);

        $this->assertCount(1, $HeaderBag->get());

        $headerString = (string) $HeaderBag->get()[0];

        $this->assertSame("Content-Security-Policy-Report-Only: default-src 'nonce-1234' 'strict-dynamic'", $headerString);
    }

    public function testSDInjectedInCSPROExclusive()
    {
        $HeaderBag = HeaderBag::fromHeaderLines([
            "Content-Security-Policy: default-src 'nonce-1234'",
            "Content-Security-Policy-Report-Only: default-src 'nonce-1234'",
        ]);

        $InjSD = new InjectStrictDynamic($this->algs, InjectStrictDynamic::REPORT);
        $InjSD->modify($HeaderBag);

        $this->assertCount(2, $HeaderBag->get());

        $this->assertNotContains('strict-dynamic', (string) $HeaderBag->get()[0]);

        $headerString = (string) $HeaderBag->get()[1];

        $this->assertSame("Content-Security-Policy-Report-Only: default-src 'nonce-1234' 'strict-dynamic'", $headerString);
    }

    public function testSDInjectedInCSPExclusive()
    {
        $HeaderBag = HeaderBag::fromHeaderLines([
            "Content-Security-Policy: default-src 'nonce-1234'",
            "Content-Security-Policy-Report-Only: default-src 'nonce-1234'",
        ]);

        $InjSD = new InjectStrictDynamic($this->algs, InjectStrictDynamic::ENFORCE);
        $InjSD->modify($HeaderBag);

        $this->assertCount(2, $HeaderBag->get());

        $this->assertNotContains('strict-dynamic', (string) $HeaderBag->get()[1]);

        $headerString = (string) $HeaderBag->get()[0];

        $this->assertSame("Content-Security-Policy: default-src 'nonce-1234' 'strict-dynamic'", $headerString);
    }
}
