<?php

namespace Aidantwoods\SecureHeaders\Tests;

use Aidantwoods\SecureHeaders\HeaderFactory;
use PHPUnit_Framework_TestCase;

class HeaderFactoryTest extends PHPUnit_Framework_TestCase
{
    public function provideCSPHeaders()
    {
        return [
            ['Content-SECURITY-Policy', "default-src 'none'"],
            ['ConTeNt-Security-Policy-Report-Only', "default-src 'none'"],
            ['x-Content-Security-POLICY', "default-src 'none'"],
            ['X-content-security-policy-report-only', "default-src 'none'"],
        ];
    }

    /**
     * @dataProvider provideCSPHeaders
     * @param $name
     * @param $value
     */
    public function testCSPHeaders($name, $value)
    {
        $Header = HeaderFactory::build($name, $value);

        $this->assertInstanceOf(
            'Aidantwoods\SecureHeaders\Headers\CSPHeader',
            $Header
        );
    }

    public function provideRegularHeaders()
    {
        return [
            ['Set-Cookie', 'foo=bar'],
            ['FooBar', 'baz boo'],
        ];
    }

    /**
     * @dataProvider provideRegularHeaders
     * @param $name
     * @param $value
     */
    public function testRegularHeaders($name, $value)
    {
        $Header = HeaderFactory::build($name, $value);

        $this->assertInstanceOf(
            'Aidantwoods\SecureHeaders\Headers\RegularHeader',
            $Header
        );
    }
}
