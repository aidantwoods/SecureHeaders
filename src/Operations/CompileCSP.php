<?php

namespace Aidantwoods\SecureHeaders\Operations;

use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Operation;
use Aidantwoods\SecureHeaders\Util\Types;

class CompileCSP implements Operation
{
    private $cspConfig;
    private $csproConfig;
    private $csproBlacklist;
    private $sendLegacyHeaders;
    private $combine;

    /**
     * Create an operation to compile and add given CSPs from $cspConfig,
     * $csproConfig, with $csproBlacklist.
     *
     * $sendLegacyHeaders will duplicate the policies to legacy headers and
     * add those too.
     *
     * $combineMultiplePolicies will decide whether to merge (combine) multiple
     * policies (policies already in headers from the HeaderBag given to
     * {@see modify}) with the given policies, or whether to simply send
     * additional policy headers.
     *
     * @param array $cspConfig
     * @param array $csproConfig
     * @param array $csproBlacklist
     * @param bool $sendLegacyHeaders
     * @param bool $combineMultiplePolicies
     */
    public function __construct(
        array $cspConfig,
        array $csproConfig,
        array $csproBlacklist = [],
        $sendLegacyHeaders = false,
        $combineMultiplePolicies = true
    ) {
        Types::assert(
            ['bool' => [$sendLegacyHeaders, $combineMultiplePolicies]],
            [4, 5]
        );

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
        $cspHeaders = [
            'Content-Security-Policy' => 'csp',
            'Content-Security-Policy-Report-Only' => 'cspro',
        ];

        foreach ($cspHeaders as $header => $type)
        {
            if ($this->combine)
            {
                $otherPolicyHeaders = $headers->getByName($header);

                $policies = [$this->{$type.'Config'}];

                foreach ($otherPolicyHeaders as $otherPolicy)
                {
                    $policies[]
                        = self::deconstructCSP($otherPolicy->getValue());
                }

                $this->{$type.'Config'} = self::mergeCSPList($policies);
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

    /**
     * Compile internal CSP config into a CSP header-value string
     *
     * @return string
     */
    private function compileCSP()
    {
        return self::compile($this->cspConfig);
    }

    /**
     * Compile internal CSPRO config into a CSP header-value string
     *
     * @return string
     */
    private function compileCSPRO()
    {
        # Filter out the blacklisted directives
        $filteredConfig = array_diff_key(
            $this->csproConfig,
            array_flip($this->csproBlacklist)
        );

        return self::compile($filteredConfig);
    }

    /**
     * Compile CSP $config into a CSP header-value string
     *
     * @param array $config
     * @return string
     */
    public static function compile(array $config)
    {
        $pieces = [];

        foreach ($config as $directive => $sources)
        {
            if (is_array($sources))
            {
                self::removeEmptySources($sources);
                self::removeDuplicateSources($sources);

                array_unshift($sources, $directive);

                $pieces[] = implode(' ', $sources);
            }
            else
            {
                $pieces[] = $directive;
            }
        }

        return implode('; ', $pieces);
    }

    /**
     * Deconstruct $cspString into a CSP config array
     *
     * @param string $cspString
     * @return array
     */
    public static function deconstructCSP($cspString)
    {
        $csp = [];

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

                $sources = explode(' ', $sourcesString);

                self::removeEmptySources($sources);
            }
            else
            {
                $sources = true;
            }

            $csp[$directive] = $sources;
        }

        return $csp;
    }

    /**
     * Remove empty sources from $sources
     *
     * @param array $sources
     * @return void
     */
    private static function removeEmptySources(array &$sources)
    {
        $sources = array_filter(
            $sources,
            function ($source)
            {
                return $source !== '';
            }
        );
    }

    /**
     * Remove duplicate sources from $sources
     *
     * @param array $sources
     * @return void
     */
    private static function removeDuplicateSources(array &$sources)
    {
        $sources = array_unique($sources, SORT_REGULAR);
    }

    /**
     * Merge a multiple CSP configs together into a single CSP
     *
     * @param array $cspList
     * @return array
     */
    public static function mergeCSPList(array $cspList)
    {
        $finalCSP = [];

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
