<?php

namespace Aidantwoods\SecureHeaders\Tests\Headers;

use Aidantwoods\SecureHeaders\Headers\RegularHeader;
use PHPUnit_Framework_TestCase;

class RegularHeaderTest extends PHPUnit_Framework_TestCase
{
    public function testInjectFlag()
    {
        $Header = new RegularHeader('Set-Cookie', 'foo=bar');

        $Header->setAttribute('Secure');

        $this->assertSame(
            'Set-Cookie: foo=bar; Secure',
            (string) $Header
        );
    }

    public function testInjectAttribute()
    {
        $Header = new RegularHeader('Set-Cookie', 'foo=bar');

        $Header->setAttribute('baz', 'boo');

        $this->assertSame(
            'Set-Cookie: foo=bar; baz=boo',
            (string) $Header
        );
    }

    public function testAttributeIsRemoved()
    {
        $Header = new RegularHeader('Set-Cookie', 'foo=bar');

        $Header->setAttribute('baz', 'boo');

        $this->assertSame(
            'Set-Cookie: foo=bar; baz=boo',
            (string) $Header
        );

        $Header->removeAttribute('baz');

        $this->assertSame(
            'Set-Cookie: foo=bar',
            (string) $Header
        );
    }

    public function testAttributeSetToFalseIsRemoved()
    {
        $Header = new RegularHeader('Set-Cookie', 'foo=bar');

        $Header->setAttribute('baz', 'boo');

        $this->assertSame(
            'Set-Cookie: foo=bar; baz=boo',
            (string) $Header
        );

        $Header->setAttribute('baz', false);

        $this->assertSame(
            'Set-Cookie: foo=bar',
            (string) $Header
        );
    }

    public function testAttributeReplaced()
    {
        $Header = new RegularHeader('Set-Cookie', 'foo=bar');

        $Header->setAttribute('foo', 'boo');

        $this->assertSame(
            'Set-Cookie: foo=boo',
            (string) $Header
        );
    }

    public function testValueReplaced()
    {
        $Header = new RegularHeader('Set-Cookie', 'foo=bar');

        $Header->setValue('Big bad wolf');

        $this->assertSame(
            'Set-Cookie: Big bad wolf',
            (string) $Header
        );
    }

    public function testHasAttribute()
    {
        $Header = new RegularHeader('Set-Cookie', 'foo=bar');

        $this->assertSame(
            false,
            $Header->hasAttribute('bar')
        );

        $this->assertSame(
            true,
            $Header->hasAttribute('foo')
        );
    }

    public function testEnsureAttributeMaximum()
    {
        $Header = new RegularHeader('Set-Cookie', 'foo=100; bar=100');

        $Header->ensureAttributeMaximum('foo', 10);
        $Header->ensureAttributeMaximum('bar', 1000);

        $this->assertSame(
            'Set-Cookie: foo=10; bar=100',
            (string) $Header
        );
    }
}
