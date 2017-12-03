<?php

namespace Aidantwoods\SecureHeaders\Operations;

use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Operation;

class CompileHPKP implements Operation
{
    private $pkpConfig;
    private $pkproConfig;

    /**
     * Create an Operation to add (in replace mode) an HPKP header with
     * $pkpConfig, and an HPKPRO header with $pkproConfig. If configs are
     * empty, no header will be added.
     *
     * @param array $pkpConfig
     * @param array $pkpConfig
     */
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
    public function modify(HeaderBag &$headers)
    {
        $hpkpHeaders = [
            'Public-Key-Pins' => $this->compilePKP(),
            'Public-Key-Pins-Report-Only' => $this->compilePKPRO(),
        ];

        foreach ($hpkpHeaders as $header => $value)
        {
            if (empty($value))
            {
                continue;
            }

            $headers->replace($header, $value);
        }
    }

    /**
     * Compile internal HPKP config into a HPKP header-value string
     *
     * @return string
     */
    private function compilePKP()
    {
        return $this->compile($this->pkpConfig);
    }

    /**
     * Compile internal HPKPRO config into a HPKPRO header-value string
     *
     * @return string
     */
    private function compilePKPRO()
    {
        return $this->compile($this->pkproConfig);
    }

    /**
     * Compile HPKP $config into a HPKP header-value string
     *
     * @param array $config
     * @return string
     */
    private function compile(array $config)
    {
        if (empty($config) or empty($config['pins']))
        {
            return '';
        }

        $maxAge = isset($config['max-age']) ? $config['max-age'] : 10;

        $pieces = ["max-age=$maxAge"];

        foreach ($config['pins'] as $pinAlg)
        {
            list($pin, $alg) = $pinAlg;

            $pieces[] = "pin-$alg=\"$pin\"";
        }

        if ($config['includesubdomains'])
        {
            $pieces[] = 'includeSubDomains';
        }

        if ($config['report-uri'])
        {
            $pieces[] = 'report-uri="' . $config['report-uri'] . '"';
        }

        return implode('; ', $pieces);
    }
}
