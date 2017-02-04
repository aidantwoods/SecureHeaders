<?php

namespace Aidantwoods\SecureHeaders;

interface Operation
{
    /**
     * Transform the given set of headers
     *
     * If an implementation also implements ExposesErrors, errors should be
     * cleared on calling `modify`
     *
     * @param HeaderBag $headers
     * @return void
     */
    public function modify(HeaderBag &$headers);
}
