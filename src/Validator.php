<?php

namespace Aidantwoods\SecureHeaders;

abstract class Validator
{
    public const CSP   = 'content-security-policy';
    public const CSPRO = 'content-security-policy-report-only';

    public const VALIDATOR_NAMESPACE = 'Aidantwoods\SecureHeaders\ValidatorDelegates';

    private static $delegates = [
        'CSPBadFlags'
            => [self::CSP, self::CSPRO],
        'CSPWildcards'
            => [self::CSP, self::CSPRO],
        'CSPRODestination'
            => self::CSPRO
    ];

    /**
     * Validate the given headers
     *
     * @param HeaderBag $headers
     *
     * @return Error[]
     */
    public static function validate(HeaderBag $headers)
    {
        $errors = [];

        foreach (self::$delegates as $delegate => $headerList)
        {
            $class = self::VALIDATOR_NAMESPACE.'\\'.$delegate;

            if ( ! is_array($headerList))
            {
                $headerList = [$headerList];
            }

            foreach ($headerList as $headerName)
            {
                $headers->forEachNamed(
                    $headerName,
                    function (Header $header) use (&$errors, $class)
                    {
                        $errors = array_merge(
                            $errors,
                            $class::validate($header)
                        );
                    }
                );
            }
        }

        return $errors;
    }
}
