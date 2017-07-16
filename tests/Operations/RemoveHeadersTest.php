<?php

namespace Aidantwoods\SecureHeaders\Tests\Operations;

use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Operations\RemoveHeaders;
use PHPUnit_Framework_TestCase;

class RemoveHeadersTest extends PHPUnit_Framework_TestCase
{
    public function testCorrectHeadersRemoved()
    {
        $HeaderBag = HeaderBag::fromHeaderLines([
            "FooBar: nope=1",
            "foobar: nope=2",
            "foo-bar: noPe=3",
            "foobar:",
        ]);

        $RemoveHeaders = new RemoveHeaders(['FOOBAR']);
        $RemoveHeaders->modify($HeaderBag);

        $this->assertCount(1, $HeaderBag->get());

        $headerString = (string) $HeaderBag->get()[0];

        $this->assertSame('foo-bar: noPe=3', $headerString);
    }
}
