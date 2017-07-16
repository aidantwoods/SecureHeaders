<?php

namespace Aidantwoods\SecureHeaders\Tests\ValidatorDelegates;

use Aidantwoods\SecureHeaders\ValidatorDelegates\CSPRODestination;
use Aidantwoods\SecureHeaders\HeaderFactory;
use Aidantwoods\SecureHeaders\Error;
use PHPUnit_Framework_TestCase;

class CSPRODestinationTest extends PHPUnit_Framework_TestCase
{
    protected static $errorMsg =
        'Content Security Policy Report Only header was sent,
        but an invalid, unsafe, or no reporting address was given.
        This header will not enforce violations, and with no
        reporting address specified, the browser can only
        report them locally in its console. Consider adding a
        reporting address to make full use of this header.'
    ;

    public function provideDestinationCases()
    {
        return [
            ["default-src 'unsafe-inline'"],
            ["default-src 'unsafe-inline'; report-uri https://a"],
            ["default-src 'unsafe-inline'; report-uri http://a.com"],
            ["default-src 'unsafe-inline'; report-uri https://a.com", false],
            ["default-src 'unsafe-inline'; report-uri https://a?.com"],
        ];
    }

    /**
     * @dataProvider provideDestinationCases
     * @param $headerValue
     * @param $expectError
     */
    public function testDestinations($headerValue, $expectError = true)
    {
        $BadCSP = HeaderFactory::build(
            'Content-Security-Policy-Report-Only',
            $headerValue
        );

        $Errors = CSPRODestination::validate($BadCSP);

        if ($expectError)
        {
            $this->assertCount(1, $Errors);
            $this->assertEquals(
                new Error(static::$errorMsg, E_USER_NOTICE),
                $Errors[0]
            );
        }
        else
        {
            $this->assertCount(0, $Errors);
        }
    }
}
