<?php

namespace Aidantwoods\SecureHeaders;

interface Operation
{
    /**
     * Transform the given set of headers
     *
     * @param HeaderBag $headers
     * @return void
     */
    public function modify(HeaderBag &$headers);
}
