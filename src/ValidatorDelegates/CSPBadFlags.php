<?php

namespace Aidantwoods\SecureHeaders\ValidatorDelegates;

use Aidantwoods\SecureHeaders\Error;
use Aidantwoods\SecureHeaders\Header;
use Aidantwoods\SecureHeaders\ValidatorDelegate;
use Aidantwoods\SecureHeaders\Util\Types;

class CSPBadFlags implements ValidatorDelegate
{
    /**
     * Validate the given header
     *
     * @param Header $header
     *
     * @return Error[]
     */
    public static function validate(Header $header)
    {
        $Errors = [];

        $Errors = array_merge(
            $Errors,
            self::validateSrcAttribute($header, 'default-src'),
            self::validateSrcAttribute($header, 'script-src')
        );

        return array_values(array_filter($Errors));
    }

    /**
     * Find bad flags in the given attribute
     *
     * @param Header $header
     * @param string $attributeName
     *
     * @return Error[]
     */
    private static function validateSrcAttribute(Header $header, $attributeName)
    {
        Types::assert(['string' => [$attributeName]], [2]);

        $Errors = [];

        if ($header->hasAttribute($attributeName))
        {
            $value = $header->getAttributeValue($attributeName);

            $badFlags = ["'unsafe-inline'", "'unsafe-eval'"];
            foreach ($badFlags as $badFlag)
            {
                if (strpos($value, $badFlag) !== false)
                {
                    $friendlyHeader = $header->getFriendlyName();

                    $Errors[] = new Error(
                        $friendlyHeader . ' contains the <b>'
                        . $badFlag . '</b> keyword in <b>' . $attributeName
                        . '</b>, which prevents CSP protecting
                                against the injection of arbitrary code
                                into the page.',

                        E_USER_WARNING
                    );
                }
            }
        }

        return $Errors;
    }
}
