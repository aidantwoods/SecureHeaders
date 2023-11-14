<?php

namespace Aidantwoods\SecureHeaders\Tests;

use Aidantwoods\SecureHeaders\Http\StringHttpAdapter;
use Aidantwoods\SecureHeaders\SecureHeaders;
use PHPUnit\Framework\TestCase;

class StrictModeHeadersTest extends TestCase
{
    private $assertions = [
        'StringContainsString',
        'StringNotContainsString',
        'Equals',
        'MatchesRegularExpression',
        'DoesNotMatchRegularExpression'
    ];

    public static function dataStrictMode()
    {
        return [
            [
                'test' =>
                    function (&$headers)
                    {
                        $headers->strictMode();
                    },
                'assertions' => [
                    'StringContainsString' =>
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
                    'StringContainsString' =>
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
                    'MatchesRegularExpression' =>
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
                    'MatchesRegularExpression' =>
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
                    'MatchesRegularExpression' =>
                        "/script-src 'nonce-[^']+' 'strict-dynamic'/",
                    'DoesNotMatchRegularExpression' =>
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
                    'MatchesRegularExpression' =>
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
                    'MatchesRegularExpression' =>
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
                    'MatchesRegularExpression' =>
                        "/script-src 'sha[^']+' 'strict-dynamic'/",
                    'DoesNotMatchRegularExpression' =>
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
                    'StringNotContainsString' =>
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
