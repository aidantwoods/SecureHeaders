<?php

namespace Tests\Util;

use Aidantwoods\SecureHeaders\Util\Types;
use PHPUnit_Framework_TestCase;
use stdClass;

class TypesTest extends PHPUnit_Framework_TestCase
{
    /**
     * @dataProvider validValues
     */
    public function testValidValues($type, $variable)
    {
        $result = Types::assert(array(
            $type => array($variable)
        ));

        $this->assertNull($result);
    }

    public function validValues()
    {
        return array(
            array('string', 'abcde'),
            array('string', null),
            array('integer', 42),
            array('integer', null),
            array('double', 1.5),
            array('double', null),
            array('bool', false),
            array('bool', true),
            array('bool', null),
            array('boolean', false),
            array('boolean', true),
            array('boolean', null),
            array('object', new stdClass()),
            array('object', null),
        );
    }

    /**
     * @dataProvider invalidValues
     */
    public function testInvalidStringsRaiseExceptions($type, $variable)
    {
        $this->setExpectedException('Aidantwoods\SecureHeaders\Util\TypeError');

        Types::assert(array(
            $type => array($variable)
        ));
    }

    public function invalidValues()
    {
        return array(
            array('string', 42),
            array('string', 1.5),
            array('string', false),
            array('string', true),
            array('string', new stdClass()),
            array('integer', 'abcde'),
            array('integer', 1.5),
            array('integer', false),
            array('integer', true),
            array('integer', new stdClass()),
            array('double', 'abcde'),
            array('double', 42),
            array('double', false),
            array('double', true),
            array('double', new stdClass()),
            array('bool', 'abcde'),
            array('bool', 42),
            array('bool', 1.5),
            array('bool', new stdClass()),
            array('boolean', 'abcde'),
            array('boolean', 42),
            array('boolean', 1.5),
            array('boolean', new stdClass()),
            array('object', 'abcde'),
            array('object', 42),
            array('object', 1.5),
            array('object', false),
            array('object', true),
        );
    }
}
