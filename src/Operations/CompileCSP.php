<?php

namespace Aidantwoods\SecureHeaders\Operations;

use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Operation;

class CompileCSP implements Operation
{
    private $cspConfig;
    private $csproConfig;
    private $csproBlacklist;
    private $sendLegacyHeaders;

    public function __construct(
        array $cspConfig,
        array $csproConfig,
        array $csproBlacklist = array(),
        $sendLegacyHeaders = false
    ) {
        $this->cspConfig = $cspConfig;
        $this->csproConfig = $csproConfig;
        $this->csproBlacklist = $csproBlacklist;

        $this->sendLegacyHeaders = $sendLegacyHeaders;
    }

    /**
     * Transform the given set of headers
     *
     * @param HeaderBag $headers
     * @return void
     */
    public function modify(HeaderBag $headers)
    {
        $cspHeaders = array(
            'Content-Security-Policy' => $this->compileCSP(),
            'Content-Security-Policy-Report-Only' => $this->compileCSPRO(),
        );

        foreach ($cspHeaders as $header => $value) {
            if (empty($value)) {
                continue;
            }

            $headers->replace($header, $value);

            if ($this->sendLegacyHeaders) {
                $headers->replace("X-$header", $value);
            }
        }
    }

    private function compileCSP()
    {
        return $this->compile($this->cspConfig);
    }

    private function compileCSPRO()
    {
        // Filter out the blacklisted directives
        $filteredConfig = array_diff_key(
            $this->csproConfig,
            array_flip($this->csproBlacklist)
        );

        return $this->compile($filteredConfig);
    }

    private function compile($config)
    {
        $pieces = array();

        foreach ($config as $directive => $sources)
        {
            if (is_array($sources)) {
                array_unshift($sources, $directive);
                $pieces[] = implode(' ', $sources);
            } else {
                $pieces[] = $directive;
            }
        }

        return implode('; ', $pieces);
    }
}
