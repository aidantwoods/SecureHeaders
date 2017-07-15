<?php

namespace Aidantwoods\SecureHeaders\Tests\Operations;

use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Operations\CompileHPKP;
use PHPUnit_Framework_TestCase;

class CompileHPKPTest extends PHPUnit_Framework_TestCase
{
    public function provideHPKPTestCases()
    {
        return [
            [
                [
                    'max-age' => 31536000,
                    'pins' => [['abc-123', 'sha256'], ['efg-456', 'sha256']],
                    'includesubdomains' => true,
                    'report-uri' => 'https://report.example.com',
                ],
                'max-age=31536000; pin-sha256="abc-123"; pin-sha256="efg-456"; includeSubDomains; report-uri="https://report.example.com"'
            ],
            [
                [
                    'max-age' => 31536000,
                    'pins' => [['abc-123', 'sha256'], ['efg-456', 'sha256']],
                    'includesubdomains' => true,
                    'report-uri' => false,
                ],
                'max-age=31536000; pin-sha256="abc-123"; pin-sha256="efg-456"; includeSubDomains'
            ],
            [
                [
                    'max-age' => 31536000,
                    'pins' => [['abc-123', 'sha256'], ['efg-456', 'sha256']],
                    'includesubdomains' => false,
                    'report-uri' => false,
                ],
                'max-age=31536000; pin-sha256="abc-123"; pin-sha256="efg-456"'
            ],
            [
                [
                    'max-age' => 31536000,
                    'pins' => [['abc-123', 'sha256'], ['efg-456', 'sha256']],
                    'includesubdomains' => false,
                    'report-uri' => 'https://report.example.com'
                ],
                'max-age=31536000; pin-sha256="abc-123"; pin-sha256="efg-456"; report-uri="https://report.example.com"'
            ],
            [
                [
                    'max-age' => '0',
                    'pins' => [['abc-123', 'sha256'], ['efg-456', 'sha256']],
                    'includesubdomains' => false,
                    'report-uri' => false,
                ],
                'max-age=0; pin-sha256="abc-123"; pin-sha256="efg-456"'
            ],
            [
                [
                    'max-age' => '1234',
                    'pins' => [['abc-123', 'sha256'], ['efg-456', 'sha256']],
                    'includesubdomains' => false,
                    'report-uri' => false,
                ],
                'max-age=1234; pin-sha256="abc-123"; pin-sha256="efg-456"'
            ],
        ];
    }

    /**
     * @dataProvider provideHPKPTestCases
     * @param $compileHPKPConfig
     * @param $expectedHeader
     */
    public function testHPKP(array $compileHPKPConfig, $expectedHeader)
    {
        $HeaderBag = new HeaderBag;

        $CompileHPKP = new CompileHPKP($compileHPKPConfig, []);
        $CompileHPKP->modify($HeaderBag);

        $this->assertCount(1, $HeaderBag->get());

        $headersString = (string) $HeaderBag->get()[0];

        $this->assertSame("Public-Key-Pins: $expectedHeader", $headersString);
    }

    /**
     * @dataProvider provideHPKPTestCases
     * @param $compileHPKPConfig
     * @param $expectedHeader
     */
    public function testHPKPRO(array $compileHPKPConfig, $expectedHeader)
    {
        $HeaderBag = new HeaderBag;

        $CompileHPKP = new CompileHPKP([], $compileHPKPConfig);
        $CompileHPKP->modify($HeaderBag);

        $this->assertCount(1, $HeaderBag->get());

        $headersString = (string) $HeaderBag->get()[0];

        $this->assertSame(
            "Public-Key-Pins-Report-Only: $expectedHeader",
            $headersString
        );
    }

    /**
     * @dataProvider provideHPKPTestCases
     * @param $compileHPKPConfig
     * @param $expectedHeader
     */
    public function testHPKPAndHPKPRO(array $compileHPKPConfig, $expectedHeader)
    {
        $HeaderBag = new HeaderBag;

        $CompileHPKP = new CompileHPKP($compileHPKPConfig, $compileHPKPConfig);
        $CompileHPKP->modify($HeaderBag);

        $this->assertCount(2, $HeaderBag->get());

        $headersString0 = (string) $HeaderBag->get()[0];
        $headersString1 = (string) $HeaderBag->get()[1];

        $this->assertSame(
            "Public-Key-Pins: $expectedHeader",
            $headersString0
        );

        $this->assertSame(
            "Public-Key-Pins-Report-Only: $expectedHeader",
            $headersString1
        );
    }

    public function testReplacesExistingHeader()
    {
        $HeaderBag = HeaderBag::fromHeaderLines([
            'Public-Key-Pins: max-age=1234',
            'Public-Key-Pins-Report-Only: max-age=1234'
        ]);

        $config = [
            'max-age' => '31536000',
            'pins' => [['abc-123', 'sha256'], ['efg-456', 'sha256']],
            'includesubdomains' => true,
            'report-uri' => false,
        ];

        $CompileHPKP = new CompileHPKP($config, $config);
        $CompileHPKP->modify($HeaderBag);

        $this->assertCount(2, $HeaderBag->get());

        $headersString0 = (string) $HeaderBag->get()[0];
        $headersString1 = (string) $HeaderBag->get()[1];

        $headerNames = ['Public-Key-Pins', 'Public-Key-Pins-Report-Only'];

        foreach ($headerNames as $key => $headerName)
        {
            $this->assertSame(
                $headerName.': max-age=31536000; pin-sha256="abc-123"; pin-sha256="efg-456"; includeSubDomains',
                ${"headersString$key"}
            );
        }
    }
}
