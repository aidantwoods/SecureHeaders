<?php

namespace Aidantwoods\SecureHeaders\Tests;

use Aidantwoods\SecureHeaders\HeaderFactory;
use PHPUnit_Framework_TestCase;

class HeaderFactoryTest extends PHPUnit_Framework_TestCase
{
    public function testCSPHeaders()
    {
        $CSPHeader = HeaderFactory::build(
            'Content-SECURITY-Policy',
            "default-src 'none'"
        );

        $CSPROHeader = HeaderFactory::build(
            'ConTeNt-Security-Policy-Report-Only',
            "default-src 'none'"
        );

        $XCSPHeader = HeaderFactory::build(
            'x-Content-Security-POLICY',
            "default-src 'none'"
        );

        $XCSPROHeader = HeaderFactory::build(
            'X-content-security-policy-report-only',
            "default-src 'none'"
        );

        $Headers = [$CSPHeader, $CSPROHeader, $XCSPHeader, $XCSPROHeader];

        foreach ($Headers as $Header)
        {
            $this->assertSame(
                'Aidantwoods\SecureHeaders\Headers\CSPHeader',
                get_class($Header)
            );
        }
    }

    public function testRegularHeaders()
    {
        $Header1 = HeaderFactory::build(
            'Set-Cookie',
            'foo=bar'
        );

        $Header2 = HeaderFactory::build(
            'FooBar',
            'baz boo'
        );

        $Headers = [$Header1, $Header2];

        foreach ($Headers as $Header)
        {
            $this->assertSame(
                'Aidantwoods\SecureHeaders\Headers\RegularHeader',
                get_class($Header)
            );
        }
    }
}
