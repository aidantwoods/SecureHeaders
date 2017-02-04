<?php

namespace Aidantwoods\SecureHeaders;
use Aidantwoods\SecureHeaders\Error;

interface OperationWithErrors extends Operation
{
    /**
     * Return an array of errors
     *
     * @param void
     * @return Error[]
     */
    public function collectErrors();

    /**
     * Clear any stored errors, then:
     * transform the given set of headers
     *
     * @param HeaderBag $headers
     * @return void
     */
    public function modify(HeaderBag &$headers);
}
