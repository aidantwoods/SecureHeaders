<?php

namespace Aidantwoods\SecureHeaders\Tests\Operations;

use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Operations\CompileExpectCT;
use PHPUnit_Framework_TestCase;

class CompileExpectCTTest extends PHPUnit_Framework_TestCase
{
    public function provideExpectCTTestCases()
    {
        return [
            [
                [
                    'max-age' => 31536000,
                    'enforce' => true,
                    'report-uri' => "https://report.example.com",
                ],
                'Expect-CT: max-age=31536000; enforce; report-uri="https://report.example.com"'
            ],
            [
                [
                    'max-age' => 31536000,
                    'enforce' => true,
                    'report-uri' => false,
                ],
                'Expect-CT: max-age=31536000; enforce'
            ],
            [
                [
                    'max-age' => 31536000,
                    'enforce' => false,
                    'report-uri' => false,
                ],
                'Expect-CT: max-age=31536000'
            ],
            [
                [
                    'max-age' => 31536000,
                    'enforce' => false,
                    'report-uri' => "https://report.example.com"
                ],
                'Expect-CT: max-age=31536000; report-uri="https://report.example.com"'
            ],
            [
                [
                    'max-age' => '0',
                    'enforce' => false,
                    'report-uri' => false,
                ],
                'Expect-CT: max-age=0'
            ],
            [
                [
                    'max-age' => '1234',
                    'enforce' => false,
                    'report-uri' => false,
                ],
                'Expect-CT: max-age=1234'
            ],
        ];
    }

    /**
     * @dataProvider provideExpectCTTestCases
     * @param $expectCTConfig
     * @param $expectedHeader
     */
    public function testExpectCT(array $expectCTConfig, $expectedHeader)
    {
        $HeaderBag = new HeaderBag;

        $CompileExpectCT = new CompileExpectCT($expectCTConfig);
        $CompileExpectCT->modify($HeaderBag);

        $headersString = (string) $HeaderBag->get()[0];

        $this->assertSame($expectedHeader, $headersString);
    }

    public function testReplacesExistingHeader()
    {
        $HeaderBag = HeaderBag::fromHeaderLines([
            'Expect-CT: max-age=1234'
        ]);

        $CompileExpectCT = new CompileExpectCT([
            'max-age' => '31536000',
            'enforce' => true,
            'report-uri' => false,
        ]);
        $CompileExpectCT->modify($HeaderBag);

        $this->assertCount(1, $HeaderBag->get());

        $headersString = (string) $HeaderBag->get()[0];

        $this->assertSame('Expect-CT: max-age=31536000; enforce', $headersString);
    }
}
