<?php

namespace Aidantwoods\SecureHeaders;

class SecureHeadersTypeError extends \Exception
{
    private $headers;

    public function passHeaders(SecureHeaders $headers)
    {
        $this->headers = $headers;
    }

    public function __toString()
    {
        header($_SERVER['SERVER_PROTOCOL'].' 500 Internal Server Error');

        $this->headers->returnBuffer();

        return 'exception '.__CLASS__." '{$this->message}'\n"."{$this->getTraceAsString()}";
    }
}