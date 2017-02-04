<?php

namespace Aidantwoods\SecureHeaders;

use Aidantwoods\SecureHeaders\Error;

interface ExposesErrors
{
    /**
     * Return an array of errors
     *
     * @param void
     * @return Error[]
     */
    public function collectErrors();
}
