<?php

namespace Aidantwoods\SecureHeaders\Util;

use Exception;

class TypeError extends Exception
{
    /**
     * Generate a TypeError with backtrace string, where $argumentNum
     * is the argument number in the errored function, $expectedType is the type
     * that was expected, and $actualType is the recieved type.
     *
     * @param int $argumentNum
     * @param string $actualType
     * @param string $actualType
     * @throws TypeError
     */
    public static function fromBacktrace($argumentNum, $expectedType, $actualType)
    {
        $backtrace = debug_backtrace();
        $caller = $backtrace[0];

        $typeError = new static(
            "Argument $argumentNum passed to "
            ."${caller['class']}::${caller['function']}() must be of"
            ." the type $expectedType, $actualType given in "
            ."${caller['file']} on line ${caller['line']}"
        );

        throw $typeError;
    }

    /**
     * Display the Exception as a string
     *
     * @return string
     */
    public function __toString()
    {
        return 'exception '.__CLASS__." '{$this->message}'\n"."{$this->getTraceAsString()}";
    }
}
