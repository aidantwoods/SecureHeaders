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
    private $combine;

    public function __construct(
        array $cspConfig,
        array $csproConfig,
        array $csproBlacklist = array(),
        $sendLegacyHeaders = false,
        $combineMultiplePolicies = true
    ) {
        $this->cspConfig = $cspConfig;
        $this->csproConfig = $csproConfig;
        $this->csproBlacklist = $csproBlacklist;

        $this->sendLegacyHeaders = $sendLegacyHeaders;
        $this->combine = $combineMultiplePolicies;
    }

    /**
     * Transform the given set of headers
     *
     * @param HeaderBag $headers
     * @return void
     */
    public function modify(HeaderBag &$headers)
    {
        $cspHeaders = array(
            'Content-Security-Policy' => 'csp',
            'Content-Security-Policy-Report-Only' => 'cspro',
        );

        foreach ($cspHeaders as $header => $type)
        {
            if ($this->combine)
            {
                $otherPolicyHeaders = $headers->getByName($header);

                $policies = array($this->{$type.'Config'});

                foreach ($otherPolicyHeaders as $otherPolicy)
                {
                    $policies[]
                        = $this->deconstructCSP($otherPolicy->getValue());
                }

                $this->{$type.'Config'} = $this->mergeCSPList($policies);
            }

            $value = $this->{'compile'.strtoupper($type)}();

            if (empty($value))
            {
                continue;
            }

            $headers->{($this->combine ? 'replace' : 'add')}($header, $value);

            if ($this->sendLegacyHeaders)
            {
                $headers->{($this->combine ? 'replace' : 'add')}("X-$header", $value);
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

    private function deconstructCSP($cspString)
    {
        $csp = array();

        $directivesAndSources = explode(';', $cspString);

        foreach ($directivesAndSources as $directiveAndSources)
        {
            $directiveAndSources = ltrim($directiveAndSources);

            $list = explode(' ', $directiveAndSources, 2);

            $directive = strtolower($list[0]);

            if (isset($csp[$directive]))
            {
                continue;
            }

            if (isset($list[1]) and trim($list[1]) !== '')
            {
                $sourcesString = $list[1];

                $sources = array_filter(
                    explode(' ', $sourcesString),
                    function($source) {
                        return $source !== '';
                    }
                );
            }
            else
            {
                $sources = true;
            }

            $csp[$directive] = $sources;
        }

        return $csp;
    }

    private function mergeCSPList(array $cspList)
    {
        $finalCSP = array();

        foreach ($cspList as $csp)
        {
            foreach ($csp as $directive => $sources)
            {
                if ( ! isset($finalCSP[$directive]))
                {
                    $finalCSP[$directive] = $sources;

                    continue;
                }
                elseif ($finalCSP[$directive] === true)
                {
                    continue;
                }
                else
                {
                    $finalCSP[$directive] = array_merge(
                        $finalCSP[$directive],
                        $sources
                    );

                    continue;
                }
            }
        }

        return $finalCSP;
    }
}
