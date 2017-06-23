<?php

namespace Aidantwoods\SecureHeaders\Operations;

use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Operation;

class ModifyCookies implements Operation
{
    private $blacklist;
    private $field;
    private $value;

    private $matchSubstring = false;

    public function __construct(array $blacklist, $field, $value = true)
    {
        $this->blacklist = $blacklist;
        $this->field = $field;
        $this->value = $value;
    }

    public static function matchingFully(array $blacklist, $field, $value = true)
    {
        return new static($blacklist, $field, $value);
    }

    public static function matchingPartially(array $blacklist, $field, $value = true)
    {
        $instance = new static($blacklist, $field, $value);
        $instance->matchSubstring = true;

        return $instance;
    }

    /**
     * Transform the given set of headers
     *
     * @param HeaderBag $headers
     * @return void
     */
    public function modify(HeaderBag &$headers)
    {
        foreach ($headers->getByName('set-cookie') as $cookieHeader)
        {
            $cookieName = $cookieHeader->getFirstAttributeName();

            if ( ! $cookieHeader->hasAttribute($this->field) and $this->matches($cookieName))
            {
                $cookieHeader->setAttribute($this->field, $this->value);
            }
        }
    }

    private function matches($cookieName)
    {
        if ($this->matchSubstring)
        {
            return $this->matchesSubstring($cookieName);
        }
        else
        {
            return $this->matchesFully($cookieName);
        }
    }

    private function matchesSubstring($cookieName)
    {
        foreach ($this->blacklist as $forbidden)
        {
            if (strpos(strtolower($cookieName), $forbidden) !== false)
            {
                return true;
            }
        }
    }

    private function matchesFully($cookieName)
    {
        return in_array(
            strtolower($cookieName),
            $this->blacklist,
            true
        );
    }
}
