<?php

namespace Tests;

use Aidantwoods\SecureHeaders\Http\StringHttpAdapter;
use Aidantwoods\SecureHeaders\SecureHeaders;
use PHPUnit_Framework_TestCase;

class StrictModeHeadersTest extends PHPUnit_Framework_TestCase
{
    private $assertions = [
        'Contains',
        'NotContains',
        'Equals',
        'Regexp',
        'NotRegExp'
    ];

    public function dataStrictMode()
    {
        return [
            [
                'test' =>
                    function (&$headers)
                    {
                        $headers->strictMode();
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
                        $headers->strictMode();
                    },
                'assertions' => [
                    'Contains' =>
                        'Expect-CT: max-age=31536000; enforce'
                ]
            ],
            [
                'test' =>
                    function (&$headers)
                    {
                        $headers->strictMode();
                        $headers->cspNonce('script');
                    },
                'assertions' => [
                    'Regexp' =>
                        "/Content-Security-Policy: script-src 'nonce-[^']+' 'strict-dynamic'/"
                ]
            ],
            [
                'test' =>
                    function (&$headers)
                    {
                        $headers->strictMode();
                        $headers->cspNonce('default');
                    },
                'assertions' => [
                    'Regexp' =>
                        "/Content-Security-Policy: default-src 'nonce-[^']+' 'strict-dynamic'/"
                ]
            ],
            [
                'test' =>
                    function (&$headers)
                    {
                        $headers->strictMode();
                        $headers->cspNonce('default');
                        $headers->cspNonce('script');
                    },
                'assertions' => [
                    'Regexp' =>
                        "/script-src 'nonce-[^']+' 'strict-dynamic'/",
                    'NotRegexp' =>
                        "/default-src 'nonce-[^']+' 'strict-dynamic'/"
                ]
            ],
            [
                'test' =>
                    function (&$headers)
                    {
                        $headers->strictMode();
                        $headers->cspHash('default', 'abcd');
                    },
                'assertions' => [
                    'Regexp' =>
                        "/Content-Security-Policy: default-src 'sha[^']+' 'strict-dynamic'/"
                ]
            ],
            [
                'test' =>
                    function (&$headers)
                    {
                        $headers->strictMode();
                        $headers->cspHash('script', 'abcd');
                    },
                'assertions' => [
                    'Regexp' =>
                        "/Content-Security-Policy: script-src 'sha[^']+' 'strict-dynamic'/"
                ]
            ],
            [
                'test' =>
                    function (&$headers)
                    {
                        $headers->strictMode();
                        $headers->cspHash('default', 'abcd');
                        $headers->cspHash('script', 'abcd');
                    },
                'assertions' => [
                    'Regexp' =>
                        "/script-src 'sha[^']+' 'strict-dynamic'/",
                    'NotRegexp' =>
                        "/default-src 'sha[^']+' 'strict-dynamic'/"
                ]
            ],
            [
                'test' =>
                    function (&$headers)
                    {
                        $headers->strictMode();
                        $headers->csp('default', 'http://some-cdn.org');
                        $headers->csp('script', 'http://other-cdn.net');
                    },
                'assertions' => [
                    'NotContains' =>
                        "'strict-dynamic'"
                ]
            ],
        ];
    }

    /**
     * @dataProvider dataStrictMode
     * @param $test
     * @param $assertions
     */
    public function testStrictMode($test, $assertions)
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
