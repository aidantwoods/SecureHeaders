<?php

namespace Aidantwoods\SecureHeaders;

interface ValidatorDelegate
{
    /**
     * Validate the given header
     *
     * @param Header $header
     *
     * @return Error[] 
     */
    public static function validate(Header $header);
}