<?php

namespace Aidantwoods\SecureHeaders\Tests\ValidatorDelegates;

use Aidantwoods\SecureHeaders\ValidatorDelegates\CSPBadFlags;
use Aidantwoods\SecureHeaders\HeaderFactory;
use Aidantwoods\SecureHeaders\Error;
use PHPUnit\Framework\TestCase;

class CSPBadFlagsTest extends TestCase
{
    public static function provideBadFlagTestCases()
    {
        return [
            [
                "default-src 'unsafe-inline'",
                [
                    new Error(
                        'Content Security Policy contains the
                        <b>\'unsafe-inline\'</b> keyword in
                        <b>default-src</b>, which prevents CSP protecting
                        against the injection of arbitrary code into
                        the page.',

                        E_USER_WARNING
                    )
                ],
            ],
            [
                "default-src 'unsafe-eval'",
                [
                    new Error(
                        'Content Security Policy contains the
                        <b>\'unsafe-eval\'</b> keyword in
                        <b>default-src</b>, which prevents CSP protecting
                        against the injection of arbitrary code into
                        the page.',

                        E_USER_WARNING
                    )
                ],
            ],
            [
                "default-src 'unsafe-inline' 'unsafe-eval'",
                [
                    new Error(
                        'Content Security Policy contains the
                        <b>\'unsafe-inline\'</b> keyword in
                        <b>default-src</b>, which prevents CSP protecting
                        against the injection of arbitrary code into
                        the page.',

                        E_USER_WARNING
                    ),
                    new Error(
                        'Content Security Policy contains the
                        <b>\'unsafe-eval\'</b> keyword in
                        <b>default-src</b>, which prevents CSP protecting
                        against the injection of arbitrary code into
                        the page.',

                        E_USER_WARNING
                    )
                ],
            ],
            [
                "script-src 'unsafe-inline'",
                [
                    new Error(
                        'Content Security Policy contains the
                        <b>\'unsafe-inline\'</b> keyword in
                        <b>script-src</b>, which prevents CSP protecting
                        against the injection of arbitrary code into
                        the page.',

                        E_USER_WARNING
                    )
                ],
            ],
            [
                "script-src 'unsafe-eval'",
                [
                    new Error(
                        'Content Security Policy contains the
                        <b>\'unsafe-eval\'</b> keyword in
                        <b>script-src</b>, which prevents CSP protecting
                        against the injection of arbitrary code into
                        the page.',

                        E_USER_WARNING
                    )
                ],
            ],
            [
                "script-src 'unsafe-inline' 'unsafe-eval'",
                [
                    new Error(
                        'Content Security Policy contains the
                        <b>\'unsafe-inline\'</b> keyword in
                        <b>script-src</b>, which prevents CSP protecting
                        against the injection of arbitrary code into
                        the page.',

                        E_USER_WARNING
                    ),
                    new Error(
                        'Content Security Policy contains the
                        <b>\'unsafe-eval\'</b> keyword in
                        <b>script-src</b>, which prevents CSP protecting
                        against the injection of arbitrary code into
                        the page.',

                        E_USER_WARNING
                    )
                ],
            ],
            [
                "default-src 'unsafe-inline' 'unsafe-eval'; "
                . "script-src 'unsafe-inline' 'unsafe-eval'",
                [
                    new Error(
                        'Content Security Policy contains the
                        <b>\'unsafe-inline\'</b> keyword in
                        <b>default-src</b>, which prevents CSP protecting
                        against the injection of arbitrary code into
                        the page.',

                        E_USER_WARNING
                    ),
                    new Error(
                        'Content Security Policy contains the
                        <b>\'unsafe-eval\'</b> keyword in
                        <b>default-src</b>, which prevents CSP protecting
                        against the injection of arbitrary code into
                        the page.',

                        E_USER_WARNING
                    ),
                    new Error(
                        'Content Security Policy contains the
                        <b>\'unsafe-inline\'</b> keyword in
                        <b>script-src</b>, which prevents CSP protecting
                        against the injection of arbitrary code into
                        the page.',

                        E_USER_WARNING
                    ),
                    new Error(
                        'Content Security Policy contains the
                        <b>\'unsafe-eval\'</b> keyword in
                        <b>script-src</b>, which prevents CSP protecting
                        against the injection of arbitrary code into
                        the page.',

                        E_USER_WARNING
                    )
                ],
            ],
        ];
    }

    /**
     * @dataProvider provideBadFlagTestCases
     * @param $headerValue
     * @param $expectedErrors
     */
    public function testBadFlags($headerValue, $expectedErrors)
    {
        $BadCSP = HeaderFactory::build('Content-Security-Policy', $headerValue);

        $Errors = CSPBadFlags::validate($BadCSP);

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
