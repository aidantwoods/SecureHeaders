<?php

namespace Aidantwoods\SecureHeaders;

interface ExposesErrors
{
    /**
     * Return an array of Errors, clearing any stored Errors
     *
     * @param void
     * @return Error[]
     */
    public function collectErrors();
}
