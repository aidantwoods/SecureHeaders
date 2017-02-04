<?php

namespace Aidantwoods\SecureHeaders\Operations;

use Aidantwoods\SecureHeaders\Error;
use Aidantwoods\SecureHeaders\Operation;
use Aidantwoods\SecureHeaders\ExposesErrors;

abstract class OperationWithErrors implements ExposesErrors
{
    private $errors;

    public function collectErrors()
    {
        return $this->errors;
    }

    protected function clearErrors()
    {
        $this->errors = array();
    }

    protected function addError($message, $level = E_USER_NOTICE)
    {
        $this->errors[] = new Error($message, $level);
    }
}
