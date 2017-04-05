<?php

namespace Aidantwoods\SecureHeaders;

class Error
{
    protected $level;
    protected $message;

    public function __construct($message, $level = E_USER_NOTICE)
    {
        $message = preg_replace('/[\\\]\n\s*/', '', $message);
        $this->message = preg_replace('/\s+/', ' ', $message);

        $this->level = $level;
    }

    public function getLevel()
    {
        return $this->level;
    }

    public function getMessage()
    {
        return $this->message;
    }

    public function __toString()
    {
        return $this->getMessage();
    }
}
