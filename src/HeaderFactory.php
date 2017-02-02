<?php

namespace Aidantwoods\SecureHeaders;

use Aidantwoods\SecureHeaders\Headers\RegularHeader;

class HeaderFactory
{
    private static $memberClasses = array(
        'content-security-policy'   => 'CSPHeader'
    );

    private static $memberNamespace = __NAMESPACE__.'\\Headers';

    public static function build($name, $value = '')
    {
        foreach (self::$memberClasses as $substring => $class)
        {
            if (strpos(strtolower($name), $substring) !== false)
            {
                $class = self::$memberNamespace."\\$class";

                return new $class($name, $value);
            }
        }

        return new RegularHeader($name, $value);
    }
}
