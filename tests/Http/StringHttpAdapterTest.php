<?php

namespace Aidantwoods\SecureHeaders\Tests\Http;

use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Http\StringHttpAdapter;
use PHPUnit\Framework\TestCase;

class StringHttpAdapterTest extends TestCase
{
    protected static $sampleHeaders = [
        'Content-Type: text/html',
        'X-Foo-Bar: val1',
        'X-Foo-Bar: val2',
    ];

    public function testProperlyFillsHeaderBag()
    {
        $adapter = new StringHttpAdapter(static::$sampleHeaders);
        $headers = $adapter->getHeaders();

        $this->assertTrue($headers->has('content-type'));
        $this->assertTrue($headers->has('x-foo-bar'));

        $this->assertCount(3, $headers->get());
    }

    public function testRemovesAllPreviousHeadersFromResponse()
    {
        $adapter = new StringHttpAdapter(static::$sampleHeaders);
        $adapter->sendHeaders(new HeaderBag());

        $this->assertEquals(new HeaderBag, $adapter->getHeaders());
        $this->assertSame('', $adapter->getSentHeaders());
    }

    public function testSendsAllHeadersFromHeaderBag()
    {
        $adapter = new StringHttpAdapter(static::$sampleHeaders);

        $adapter->sendHeaders(HeaderBag::fromHeaderLines([
            'Content-Type: text/xml',
            'Content-Length: 123',
            'Cache-Control: no-worries :)'
        ]));

        $this->assertSame(
            "Content-Type: text/xml\n"
            . "Content-Length: 123\n"
            . "Cache-Control: no-worries :)",

            $adapter->getSentHeaders()
        );
    }
}
