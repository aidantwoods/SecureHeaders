<?php

namespace Aidantwoods\SecureHeaders\Tests\Operations;

use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Operations\CompileHSTS;
use PHPUnit\Framework\TestCase;

class CompileHSTSTest extends TestCase
{
    public static function provideHSTSTestCases()
    {
        return [
            [
                [
                    'max-age' => 31536000,
                    'subdomains' => true,
                    'preload' => true,
                ],
                'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
            ],
            [
                [
                    'max-age' => 31536000,
                    'subdomains' => true,
                    'preload' => false,
                ],
                'Strict-Transport-Security: max-age=31536000; includeSubDomains'
            ],
            [
                [
                    'max-age' => 31536000,
                    'subdomains' => false,
                    'preload' => false,
                ],
                'Strict-Transport-Security: max-age=31536000'
            ],
            [
                [
                    'max-age' => 31536000,
                    'subdomains' => false,
                    'preload' => true
                ],
                'Strict-Transport-Security: max-age=31536000; preload'
            ],
            [
                [
                    'max-age' => '0',
                    'subdomains' => false,
                    'preload' => false,
                ],
                'Strict-Transport-Security: max-age=0'
            ],
            [
                [
                    'max-age' => '1234',
                    'subdomains' => false,
                    'preload' => false,
                ],
                'Strict-Transport-Security: max-age=1234'
            ],
        ];
    }

    /**
     * @dataProvider provideHSTSTestCases
     * @param $compileHSTSConfig
     * @param $expectedHeader
     */
    public function testHSTS(array $compileHSTSConfig, $expectedHeader)
    {
        $HeaderBag = new HeaderBag;

        $CompileHSTS = new CompileHSTS($compileHSTSConfig);
        $CompileHSTS->modify($HeaderBag);

        $headersString = (string) $HeaderBag->get()[0];

        $this->assertSame($expectedHeader, $headersString);
    }

    public function testReplacesExistingHeader()
    {
        $HeaderBag = HeaderBag::fromHeaderLines([
            'Strict-Transport-Security: max-age=1234'
        ]);

        $CompileHSTS = new CompileHSTS([
            'max-age' => '31536000',
            'subdomains' => true,
            'preload' => false,
        ]);
        $CompileHSTS->modify($HeaderBag);

        $this->assertCount(1, $HeaderBag->get());

        $headersString = (string) $HeaderBag->get()[0];

        $this->assertSame('Strict-Transport-Security: max-age=31536000; includeSubDomains', $headersString);
    }
}
