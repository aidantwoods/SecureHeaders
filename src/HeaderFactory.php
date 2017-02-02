<?php

namespace Aidantwoods\SecureHeaders;

use Aidantwoods\SecureHeaders\Headers\RegularHeader;

class HeaderFactory
{
    private static $memberClasses = array(
        'CSPHeader' => array(
            'content-security-policy',
            'content-security-policy-report-only',
            'x-content-security-policy',
            'x-content-security-policy-report-only'
        )
    );

    public static function build($name, $value = '')
    {
        $namespace = __NAMESPACE__.'\\Headers';

        foreach (self::$memberClasses as $class => $headerNames)
        {
            $class = "$namespace\\$class";

            foreach ($headerNames as $headerName)
            {
                if (strtolower($name) === $headerName)
                {
                    return new $class($name, $value);
                }
            }
        }

        return new RegularHeader($name, $value);
    }
}
