<?php

namespace Aidantwoods\SecureHeaders\ValidatorDelegates;

use Aidantwoods\SecureHeaders\Error;
use Aidantwoods\SecureHeaders\Header;
use Aidantwoods\SecureHeaders\ValidatorDelegate;

class csproDestination implements ValidatorDelegate
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
        $errors = array();

        if (
            ! $header->hasAttribute('report-uri')
            or  ! preg_match(
                '/https:\/\/[a-z0-9\-]+[.][a-z]{2,}.*/i',
                $header->getAttributeValue('report-uri')
            )
        ) {
            $friendlyHeader = $header->getFriendlyName();

            $errors[] = new Error($friendlyHeader.' header was sent,
                but an invalid, or no reporting address was given.
                This header will not enforce violations, and with no
                reporting address specified, the browser can only
                report them locally in its console. Consider adding
                a reporting address to make full use of this header.'
            );
        }

        return $errors;
    }
}