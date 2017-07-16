<?php

namespace Aidantwoods\SecureHeaders;

class Error
{
    protected $level;
    protected $message;

    /**
     * Create an Error with message $message, at level $level.
     *
     * @param string $message
     * @param int $level
     */
    public function __construct($message, $level = E_USER_NOTICE)
    {
        $message = preg_replace('/[\\\]\n\s*/', '', $message);
        $this->message = preg_replace('/\s+/', ' ', $message);

        $this->level = $level;
    }

    /**
     * Get the Error's level
     *
     * @return int
     */
    public function getLevel()
    {
        return $this->level;
    }

    /**
     * Get the Error's message
     *
     * @return string
     */
    public function getMessage()
    {
        return $this->message;
    }

    /**
     * Get the Error's message
     *
     * @return string
     */
    public function __toString()
    {
        return $this->getMessage();
    }
}
