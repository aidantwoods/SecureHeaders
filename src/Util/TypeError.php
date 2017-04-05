<?php

namespace Aidantwoods\SecureHeaders\Util;

use Exception;

class TypeError extends Exception
{
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

    public function __toString()
    {
        return 'exception '.__CLASS__." '{$this->message}'\n"."{$this->getTraceAsString()}";
    }
}
