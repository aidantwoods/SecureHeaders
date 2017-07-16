<?php

namespace Aidantwoods\SecureHeaders\Tests;

use Aidantwoods\SecureHeaders\Http\StringHttpAdapter;
use Aidantwoods\SecureHeaders\SecureHeaders;
use PHPUnit_Framework_TestCase;

class SafeModeTest extends PHPUnit_Framework_TestCase
{
    private $assertions = [
        'Contains',
        'NotContains',
        'Equals',
        'Regexp',
        'NotRegExp'
    ];

    public function dataSafeMode()
    {
        return [
            [
                'test' =>
                    function (&$headers)
                    {
                        $headers->hsts(31536000, true, true);
                    },
                'assertions' => [
                    'Contains' =>
                        'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
                ]
            ],
            [
                'test' =>
                    function (&$headers)
                    {
                        $headers->safeMode();
                        $headers->hsts(31536000, true, true);
                    },
                'assertions' => [
                    'NotContains' =>
                        'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
                    'Contains' =>
                        'Strict-Transport-Security: max-age=86400'
                ]
            ],
            [
                'test' =>
                    function (&$headers)
                    {
                        $headers->safeMode();
                        $headers->strictMode();
                    },
                'assertions' => [
                    'NotContains' =>
                        'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
                    'Contains' =>
                        'Strict-Transport-Security: max-age=86400'
                ]
            ],
            [
                'test' =>
                    function (&$headers)
                    {
                        $headers->safeMode();
                        $headers->hpkp('abcd', 31536000, true);
                    },
                'assertions' => [
                    'NotContains' =>
                        'max-age=31536000; pin-sha256="abcd"; includeSubDomains',
                    'Contains' =>
                        'Public-Key-Pins: max-age=10; pin-sha256="abcd"'
                ]
            ],
            [
                'test' =>
                    function (&$headers)
                    {
                        $headers->expectCT(31536000, true, 'https://report.exampe.com');
                    },
                'assertions' => [
                    'Contains' =>
                        'Expect-CT: max-age=31536000; enforce; report-uri="https://report.exampe.com"'
                ]
            ],
            [
                'test' =>
                    function (&$headers)
                    {
                        $headers->safeMode();
                        $headers->expectCT(31536000, true, 'https://report.exampe.com');
                    },
                'assertions' => [
                    'NotContains' =>
                        'Expect-CT: max-age=31536000; enforce; report-uri="https://report.exampe.com"',
                    'Contains' =>
                        'Expect-CT: max-age=31536000; report-uri="https://report.exampe.com"'
                ]
            ],
            [
                'test' =>
                    function (&$headers)
                    {
                        $headers->safeMode();
                        $headers->strictMode();
                    },
                'assertions' => [
                    'NotContains' =>
                        'Expect-CT: max-age=31536000; enforce',
                    'Contains' =>
                        'Expect-CT: max-age=31536000',
                ]
            ],
        ];
    }

    /**
     * @dataProvider dataSafeMode
     * @param $test
     * @param $assertions
     */
    public function testSafeMode($test, $assertions)
    {
        $headers = new SecureHeaders;
        $headers->errorReporting(false);
        $test($headers);
        $headers->apply($headerStrings = new StringHttpAdapter);

        $headersString = $headerStrings->getSentHeaders();

        foreach ($this->assertions as $assertion)
        {
            if (isset($assertions[$assertion]))
            {
                if ( ! is_array($assertions[$assertion]))
                {
                    $assertions[$assertion] = [$assertions[$assertion]];
                }
                foreach ($assertions[$assertion] as $assertionString)
                {
                    $this->{'assert'.$assertion}(
                        $assertionString,
                        $headersString
                    );
                }
            }
        }
    }
}
