<?php

namespace Aidantwoods\SecureHeaders\Tests;

use Aidantwoods\SecureHeaders\Error;
use PHPUnit_Framework_TestCase;

class ErrorTest extends PHPUnit_Framework_TestCase
{
    public function testMessagePreserved()
    {
        $notice  = new Error('Foo', E_USER_NOTICE);
        $warning = new Error('Bar', E_USER_WARNING);

        $this->assertSame('Foo', $notice->getMessage());
        $this->assertSame('Bar', $warning->getMessage());

        $this->assertSame('Foo', (string) $notice);
        $this->assertSame('Bar', (string) $warning);
    }

    public function testLevelPreserved()
    {
        $notice  = new Error('Foo', E_USER_NOTICE);
        $warning = new Error('Bar', E_USER_WARNING);

        $this->assertSame(E_USER_NOTICE, $notice->getLevel());
        $this->assertSame(E_USER_WARNING, $warning->getLevel());
    }
}
