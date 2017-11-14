<?php

namespace Aidantwoods\SecureHeaders\Tests\ValidatorDelegates;

use Aidantwoods\SecureHeaders\ValidatorDelegates\CSPWildcards;
use Aidantwoods\SecureHeaders\HeaderFactory;
use Aidantwoods\SecureHeaders\Error;
use PHPUnit\Framework\TestCase;

class CSPWildcardsTest extends TestCase
{
    public function provideWildcardTestCases()
    {
        return [
            [
                'default-src http: https: * *.com *a.com example.* example.com*'
                . ' data: data:* data://* example* *.co.uk *.org.uk'
                . ' *example.co.uk https://example.* https://example.*:80'
                . ' https://example.*/asd https://example.*:*',
                [
                    new Error(
                        'Content Security Policy contains the following
                        wildcards <b>http:, https:, *, *.com, *a.com,
                        example.*, example.com*, data:, data:*, data://*,
                        example*, *.co.uk, *.org.uk, *example.co.uk,
                        https://example.*, https://example.*:80,
                        https://example.*/asd, https://example.*:*</b>
                        as a source value in <b>default-src</b>; this can allow
                        anyone to insert elements covered by the
                        <b>default-src</b> directive into the page.',

                        E_USER_WARNING
                    ),
                    new Error(
                        'Content Security Policy contains the insecure protocol
                        HTTP in a source value <b>http:</b>; this can allow
                        anyone to insert elements covered by the
                        <b>default-src</b> directive into the page.',

                        E_USER_WARNING
                    )
                ]
            ],
            [
                'object-src data:',
                [
                    new Error(
                        'Content Security Policy contains a wildcard
                        <b>data:</b> as a source value in <b>object-src</b>;
                        this can allow anyone to insert elements covered by the
                        <b>object-src</b> directive into the page.',

                        E_USER_WARNING
                    ),
                ]
            ],
            [
                'img-src data:',
                []
            ],
            [
                "img-src http://example.com",
                [
                    new Error(
                        'Content Security Policy contains the insecure protocol
                        HTTP in a source value <b>http://example.com</b>; this
                        can allow anyone to insert elements covered by the
                        <b>img-src</b> directive into the page.',

                        E_USER_WARNING
                    )
                ],
            ],
        ];
    }

    /**
     * @dataProvider provideWildcardTestCases
     * @param $headerValue
     * @param $expectedErrors
     */
    public function testWildcards($headerValue, $expectedErrors)
    {
        $BadCSP = HeaderFactory::build('Content-Security-Policy', $headerValue);

        $Errors = CSPWildcards::validate($BadCSP);

        if ([] === $expectedErrors)
        {
            $this->assertCount(0, $Errors);
        }
        else
        {
            $this->assertEquals($expectedErrors, $Errors);
        }
    }
}
