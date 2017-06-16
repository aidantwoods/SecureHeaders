<?php

namespace Aidantwoods\SecureHeaders\Operations;

use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Operation;

class RemoveHeaders implements Operation
{
    private $headersToRemove;

    public function __construct(array $headersToRemove)
    {
        $this->headersToRemove = $headersToRemove;
    }

    /**
     * Transform the given set of headers
     *
     * @param HeaderBag $headers
     * @return void
     */
    public function modify(HeaderBag &$headers)
    {
        foreach ($this->headersToRemove as $header)
        {
            $headers->remove($header);
        }
    }
}
