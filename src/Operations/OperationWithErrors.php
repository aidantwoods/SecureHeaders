<?php

namespace Aidantwoods\SecureHeaders\Operations;

use Aidantwoods\SecureHeaders\Error;
use Aidantwoods\SecureHeaders\Operation;
use Aidantwoods\SecureHeaders\ExposesErrors;

abstract class OperationWithErrors implements ExposesErrors
{
    private $errors = array();

    /**
     * Return an array of errors, clearing any stored errors
     *
     * @param void
     * @return Error[]
     */
    public function collectErrors()
    {
        $errors = $this->errors;

        $this->clearErrors();

        return $errors;
    }

    /**
     * Clear any stored errors
     *
     * @param void
     * @return void
     */
    protected function clearErrors()
    {
        $this->errors = array();
    }

    /**
     * Return an array of errors, clearing any stored errors
     *
     * @param string $message
     * @param int $level
     * @return void
     */
    protected function addError($message, $level = E_USER_NOTICE)
    {
        $this->errors[] = new Error($message, $level);
    }
}
