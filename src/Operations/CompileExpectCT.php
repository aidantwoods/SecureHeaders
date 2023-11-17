<?php

namespace Aidantwoods\SecureHeaders\Operations;

use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Operation;

class CompileExpectCT implements Operation
{
    private $config;

    /**
     * Create an Operation to add (in replace mode) an Expect-CT header
     * with $expectCTConfig
     *
     * @param array $expectCTConfig
     */
    public function __construct(array $expectCTConfig)
    {
        $this->config = $expectCTConfig;
    }

    /**
     * Transform the given set of headers
     *
     * @param HeaderBag $headers
     * @return void
     */
    public function modify(HeaderBag &$headers)
    {
        $headers->replace(
            'Expect-CT',
            $this->makeHeaderValue()
        );
    }

    /**
     * Make the ExpectCT header value
     *
     * @return string
     */
    private function makeHeaderValue()
    {
        $pieces = ['max-age='.(int) $this->config['max-age']];

        if ($this->config['enforce'])
        {
            $pieces[] = 'enforce';
        }

        if ($this->config['report-uri'])
        {
            $pieces[] = 'report-uri="'.$this->config['report-uri'].'"';
        }

        return implode('; ', $pieces);
    }
}
