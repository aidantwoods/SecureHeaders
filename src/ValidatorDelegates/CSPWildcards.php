<?php

namespace Aidantwoods\SecureHeaders\ValidatorDelegates;

use Aidantwoods\SecureHeaders\Error;
use Aidantwoods\SecureHeaders\Header;
use Aidantwoods\SecureHeaders\ValidatorDelegate;

class CSPWildcards implements ValidatorDelegate
{
    const CSP_SOURCE_WILDCARD_RE
        = '/(?:[ ]|^)\K
            (?:
            # catch open protocol wildcards
                [^:.\/ ]+?
                [:]
                (?:[\/]{2})?
                [*]?
            |
            # catch domain based wildcards
                (?: # optional protocol
                    [^:. ]+?
                    [:]
                    [\/]{2}
                )?
                # optionally match domain text before *
                [^\/:* ]*?
                [*]
                (?: # optionally match TLDs after *
                    (?:[^. ]*?[.])?
                    (?:[^. ]{1,3}[.])?
                    [^. ]*
                )?
            )
            # assert that match covers the entire value
            (?=[ ;]|$)/ix';

    private static $cspSensitiveDirectives = [
        'default-src',
        'script-src',
        'style-src',
        'object-src'
    ];

    /**
     * Validate the given header
     *
     * @param Header $header
     *
     * @return Error[]
     */
    public static function validate(Header $header)
    {
        $errors = [];

        $header->forEachAttribute(
            function ($directive, $sources) use ($header, &$errors)
            {
                $errors[] = self::enumerateWildcards(
                    $header,
                    $directive,
                    $sources
                );
                $errors[] = self::enumerateNonHttps(
                    $header,
                    $directive,
                    $sources
                );
            }
        );

        return array_filter($errors);
    }

    /**
     * Find wildcards in CSP directives
     *
     * @param Header $header
     * @param $directive
     * @param $sources
     *
     * @return ?Error
     */
    private static function enumerateWildcards(
        Header $header,
        $directive,
        $sources
    ) {
        if (preg_match_all(self::CSP_SOURCE_WILDCARD_RE, $sources, $matches))
        {
            if ( ! in_array($directive, self::$cspSensitiveDirectives))
            {
                # if we're not looking at one of the above, we'll
                # be a little less strict with data:
                if (($key = array_search('data:', $matches[0])) !== false)
                {
                    unset($matches[0][$key]);
                }
            }

            if ( ! empty($matches[0]))
            {
                $friendlyHeader = $header->getFriendlyName();

                return new Error(
                    $friendlyHeader . ' ' . (count($matches[0]) > 1 ?
                        'contains the following wildcards '
                        : 'contains a wildcard ')
                    . '<b>' . implode(', ', $matches[0]) . '</b> as a
                        source value in <b>' . $directive . '</b>; this can
                        allow anyone to insert elements covered by
                        the <b>' . $directive . '</b> directive into the
                        page.',

                    E_USER_WARNING
                );
            }
        }

        return null;
    }

    /**
     * Find non secure origins in CSP directives
     *
     * @param Header $header
     * @param $directive
     * @param $sources
     *
     * @return ?Error
     */
    private static function enumerateNonHttps(
        Header $header,
        $directive,
        $sources
    ) {
        if (preg_match_all('/(?:[ ]|^)\Khttp[:][^ ]*/', $sources, $matches))
        {
            $friendlyHeader = $header->getFriendlyName();

            return new Error(
                $friendlyHeader . ' contains the insecure protocol
                    HTTP in ' . (count($matches[0]) > 1 ?
                    'the following source values '
                    : 'a source value ')
                . '<b>' . implode(', ', $matches[0]) . '</b>; this can
                    allow anyone to insert elements covered by the
                    <b>' . $directive . '</b> directive into the page.',

                E_USER_WARNING
            );
        }

        return null;
    }
}
