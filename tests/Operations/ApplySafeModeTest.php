<?php

namespace Aidantwoods\SecureHeaders\Tests\Operations;

use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Operations\ApplySafeMode;
use PHPUnit_Framework_TestCase;

class ApplySafeModeTest extends PHPUnit_Framework_TestCase
{
    public function testSTSMaxAgeWillBeReducedToOneDay()
    {
        $headers = HeaderBag::fromHeaderLines([
            'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            'Strict-Transport-Security: max-age=31536000; includeSubdomains; PreLoad',
            'Strict-Transport-Security: max-age=31536000; includesubdomains; preLoad',
            'Strict-Transport-Security: max-age=31536000; iNCLUDEsUBdOMAINS; Preload',
        ]);

        $operation = new ApplySafeMode();
        $operation->modify($headers);

        foreach ($headers->get() as $header)
        {
            $this->assertEquals(
                'max-age=86400',
                $header->getValue()
            );
        }
    }

    public function testPKPMaxAgeWillBeReducedTo10Seconds()
    {
        $headers = HeaderBag::fromHeaderLines([
            'Public-Key-Pins: pin-sha256="abc"; pin-sha256="def"; max-age=5184000; includeSubDomains; report-uri="www"',
        ]);

        $operation = new ApplySafeMode();
        $operation->modify($headers);

        $allHeaders = $headers->get();

        $this->assertEquals(
            'pin-sha256="abc"; pin-sha256="def"; max-age=10; report-uri="www"',
            $allHeaders[0]->getValue()
        );
    }

    public function testEnforcedExpectCTWillBecomeNonEnforced()
    {
        $headers = HeaderBag::fromHeaderLines([
            'Expect-CT: max-age=31536000; enforce',
            'Expect-CT: max-age=31536000; Enforce',
            'Expect-CT: max-age=31536000; ENFORCE',
            'Expect-CT: eNFORcE; max-age=31536000',
        ]);

        $operation = new ApplySafeMode();
        $operation->modify($headers);

        foreach ($headers->get() as $header)
        {
            $this->assertEquals(
                false,
                $header->hasAttribute('enforce')
            );
        }
    }
}
