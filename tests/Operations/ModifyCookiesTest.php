<?php

namespace Aidantwoods\SecureHeaders\Tests\Operations;

use Aidantwoods\SecureHeaders\Header;
use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Operations\ModifyCookies;
use PHPUnit\Framework\TestCase;

class ModifyCookiesTest extends TestCase
{
    public function testFlagsCanBeSetBasedOnFullyMatchingCookieName()
    {
        $headers = HeaderBag::fromHeaderLines([
            'Set-Cookie: session=foo',
            'Set-Cookie: sess=foo',
        ]);

        $operation = ModifyCookies::matchingFully(
            ['sess', 'auth'],
            'HttpOnly'
        );
        $operation->modify($headers);

        $allHeaders = $headers->get();
        $this->assertFlagWasNotSet($allHeaders[0], 'HttpOnly');
        $this->assertFlagWasSet($allHeaders[1], 'HttpOnly');
    }

    public function testFlagsCanBeSetBasedOnPartiallyMatchingCookieName()
    {
        $headers = HeaderBag::fromHeaderLines([
            'Set-Cookie: session=foo',
            'Set-Cookie: sess=foo',
        ]);

        $operation = ModifyCookies::matchingPartially(
            ['sess', 'auth'],
            'Secure'
        );
        $operation->modify($headers);

        $allHeaders = $headers->get();
        $this->assertFlagWasSet($allHeaders[0], 'Secure');
        $this->assertFlagWasSet($allHeaders[1], 'Secure');
    }

    private function assertFlagWasSet(Header $header, $flag)
    {
        $this->assertNotFalse(
            strpos($header->getValue(), $flag)
        );
    }

    private function assertFlagWasNotSet(Header $header, $flag)
    {
        $this->assertFalse(
            strpos($header->getValue(), $flag)
        );
    }
}
