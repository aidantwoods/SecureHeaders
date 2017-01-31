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
    private $modifyIfExists;

    private $matchSubstring = false;

    public function __construct($headerName, $field, $value = true, $modifyIfExists = false)
    {
        $this->header = $headerName;
        $this->field = $field;
        $this->value = $value;
        $this->modifyIfExists = $modifyIfExists;
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
            if ( ! $this->modifyIfExists or $header->hasAttribute($this->field))
            {
                $header->setAttribute($this->field, $this->value);
            }
        }
    }
}
