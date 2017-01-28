<?php

namespace Aidantwoods\SecureHeaders\Operations;

use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Operation;

class CompileHPKP implements Operation
{
    private $pkpConfig;
    private $pkproConfig;

    public function __construct(array $pkpConfig, array $pkproConfig)
    {
        $this->pkpConfig = $pkpConfig;
        $this->pkproConfig = $pkproConfig;
    }

    /**
     * Transform the given set of headers
     *
     * @param HeaderBag $headers
     * @return void
     */
    public function modify(HeaderBag $headers)
    {
        $hpkpHeaders = array(
            'Public-Key-Pins' => $this->compilePKP(),
            'Public-Key-Pins-Report-Only' => $this->compilePKPRO(),
        );

        foreach ($hpkpHeaders as $header => $value) {
            if (empty($value)) {
                continue;
            }

            $headers->replace($header, $value);
        }
    }

    private function compilePKP()
    {
        return $this->compile($this->pkpConfig);
    }

    private function compilePKPRO()
    {
        return $this->compile($this->pkproConfig);
    }

    private function compile($config)
    {
        if (empty($config) or empty($config['pins'])) {
            return '';
        }

        $maxAge = isset($config['max-age']) ? $config['max-age'] : 10;

        $pieces = array("max-age=$maxAge");

        foreach ($config['pins'] as $pinAlg) {
            list($pin, $alg) = $pinAlg;

            $pieces[] = "pin-$alg=\"$pin\"";
        }

        if ($config['includesubdomains']) {
            $pieces[] = 'includeSubDomains';
        }

        if ($config['report-uri']) {
            $pieces[] = 'report-uri="' . $config['report-uri'] . '"';
        }

        return implode('; ', $pieces);
    }
}
