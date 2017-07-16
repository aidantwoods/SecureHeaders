<?php

namespace Aidantwoods\SecureHeaders\Tests\Operations;

use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Operations\RemoveCookies;
use PHPUnit_Framework_TestCase;

class RemoveCookiesTest extends PHPUnit_Framework_TestCase
{
    public function testCorrectCookiesRemoved()
    {
        $HeaderBag = HeaderBag::fromHeaderLines([
            "Set-Cookie: nope=1",
            "Set-Cookie: nope=2",
            "Set-Cookie: noPe=3",
            "Set-Cookie: noped=4",
        ]);

        $RemoveCookies = new RemoveCookies(['nope']);
        $RemoveCookies->modify($HeaderBag);

        $this->assertCount(1, $HeaderBag->get());

        $headerString = (string) $HeaderBag->get()[0];

        $this->assertSame('Set-Cookie: noped=4', $headerString);
    }
}
