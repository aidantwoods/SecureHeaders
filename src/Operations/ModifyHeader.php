<?php

namespace Aidantwoods\SecureHeaders\Operations;

use Aidantwoods\SecureHeaders\Header;
use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Operation;

class ModifyHeader implements Operation
{
    private $header;
    private $field;
    private $value;
    private $modifyAll;

    private $matchSubstring = false;

    public function __construct($headerName, $field, $value = true, $modifyAll = false)
    {
        $this->header = $headerName;
        $this->field = $field;
        $this->value = $value;
        $this->modifyAll = $modifyAll;
    }

    /**
     * Transform the given set of headers
     *
     * @param HeaderBag $headers
     * @return void
     */
    public function modify(HeaderBag &$headers)
    {
        foreach ($headers->getByName($this->header) as $header)
        {
            $header->setAttribute($this->field, $this->value);

            if ( ! $this->modifyAll)
            {
                break;
            }
        }
    }
}
