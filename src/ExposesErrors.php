<?php

namespace Aidantwoods\SecureHeaders;

interface ExposesErrors
{
    /**
     * Return an array of errors, clearing any stored errors
     *
     * @param void
     * @return Error[]
     */
    public function collectErrors();
}
