<?php

namespace Aidantwoods\SecureHeaders\Tests\Util;

use Aidantwoods\SecureHeaders\Util\Types;
use PHPUnit\Framework\TestCase;
use stdClass;

class TypesTest extends TestCase
{
    /**
     * @dataProvider validValues
     */
    public function testValidValues($type, $variable)
    {
        $result = Types::assert([
            $type => [$variable]
        ]);

        $this->assertNull($result);
    }

    public static function validValues()
    {
        return [
            ['string', 'abcde'],
            ['?string', null],
            ['integer', 42],
            ['?integer', null],
            ['int', 42],
            ['?int', null],
            ['double', 1.5],
            ['?double', null],
            ['bool', false],
            ['bool', true],
            ['?bool', null],
            ['boolean', false],
            ['boolean', true],
            ['?boolean', null],
            ['object', new stdClass()],
            ['?object', null],
        ];
    }

    /**
     * @dataProvider invalidValues
     */
    public function testInvalidStringsRaiseExceptions($type, $variable)
    {
        $this->expectException(\Aidantwoods\SecureHeaders\Util\TypeError::class);
        Types::assert([
            $type => [$variable]
        ]);
    }

    public static function invalidValues()
    {
        return [
            ['string', 42],
            ['string', 1.5],
            ['string', false],
            ['string', true],
            ['string', new stdClass()],
            ['string', null],
            ['?string', 42],
            ['?string', 1.5],
            ['?string', false],
            ['?string', true],
            ['?string', new stdClass()],
            ['integer', 'abcde'],
            ['integer', 1.5],
            ['integer', false],
            ['integer', true],
            ['integer', new stdClass()],
            ['integer', null],
            ['?integer', 'abcde'],
            ['?integer', 1.5],
            ['?integer', false],
            ['?integer', true],
            ['?integer', new stdClass()],
            ['int', 'abcde'],
            ['int', 1.5],
            ['int', false],
            ['int', true],
            ['int', new stdClass()],
            ['int', null],
            ['?int', 'abcde'],
            ['?int', 1.5],
            ['?int', false],
            ['?int', true],
            ['?int', new stdClass()],
            ['double', 'abcde'],
            ['double', 42],
            ['double', false],
            ['double', true],
            ['double', new stdClass()],
            ['double', null],
            ['?double', 'abcde'],
            ['?double', 42],
            ['?double', false],
            ['?double', true],
            ['?double', new stdClass()],
            ['bool', 'abcde'],
            ['bool', 42],
            ['bool', 1.5],
            ['bool', new stdClass()],
            ['bool', null],
            ['?bool', 'abcde'],
            ['?bool', 42],
            ['?bool', 1.5],
            ['?bool', new stdClass()],
            ['boolean', 'abcde'],
            ['boolean', 42],
            ['boolean', 1.5],
            ['boolean', new stdClass()],
            ['boolean', null],
            ['?boolean', 'abcde'],
            ['?boolean', 42],
            ['?boolean', 1.5],
            ['?boolean', new stdClass()],
            ['object', 'abcde'],
            ['object', 42],
            ['object', 1.5],
            ['object', false],
            ['object', true],
            ['object', null],
            ['?object', 'abcde'],
            ['?object', 42],
            ['?object', 1.5],
            ['?object', false],
            ['?object', true],
        ];
    }
}
