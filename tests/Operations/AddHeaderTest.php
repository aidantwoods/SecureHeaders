<?php

namespace Tests\Operations;

use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Operations\AddHeader;
use PHPUnit_Framework_TestCase;

class AddHeaderTest extends PHPUnit_Framework_TestCase
{
    public function testHeadersCanBeAdded()
    {
        $headers = HeaderBag::fromHeaderLines([
            'X-Foo: Bar',
        ]);

        $operation = new AddHeader('Location', 'index.php');
        $operation->modify($headers);

        $this->assertTrue($headers->has('x-foo'));
        $this->assertTrue($headers->has('location'));
    }

    public function testExistingHeadersAreNotReplaced()
    {
        $headers = HeaderBag::fromHeaderLines([
            'X-Foo: bar',
        ]);

        $operation = new AddHeader('x-foo', 'baz');
        $operation->modify($headers);

        $this->assertTrue($headers->has('x-foo'));

        $allHeaders = $headers->get();
        $this->assertCount(1, $allHeaders);
        $this->assertTrue($allHeaders[0]->is('x-foo'));
        $this->assertSame('bar', $allHeaders[0]->getValue());
    }
}
