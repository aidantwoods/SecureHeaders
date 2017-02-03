<?php

namespace Aidantwoods\SecureHeaders\Operations;

use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Operation;

class CompileHSTS implements Operation
{
    private $config;

    public function __construct(array $hstsConfig)
    {
        $this->config = $hstsConfig;
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
            'Strict-Transport-Security',
            $this->makeHeaderValue()
        );
    }

    private function makeHeaderValue()
    {
        $pieces = array('max-age=' . $this->config['max-age']);

        if ($this->config['subdomains']) {
            $pieces[] = 'includeSubDomains';
        }

        if ($this->config['preload']) {
            $pieces[] = 'preload';
        }

        return implode('; ', $pieces);
    }
}
