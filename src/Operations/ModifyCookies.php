<?php

namespace Aidantwoods\SecureHeaders\Operations;

use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Operation;

class ModifyCookies implements Operation
{
    private $cookieList;
    private $field;
    private $value;

    private $matchSubstring = false;

    /**
     * Create an Operation to modify cookies in $cookieList such that
     * $field holds $value.
     *
     * @param array $cookieList
     * @param string $field
     * @param $value
     */
    public function __construct(array $cookieList, $field, $value = true)
    {
        $this->cookieList = $cookieList;
        $this->field = $field;
        $this->value = $value;
    }

    /**
     * Create an Operation to modify cookies with names $cookieNames such that
     * $field holds $value.
     *
     * @param array $cookieNames
     * @param string $field
     * @param $value
     * @return Operation
     */
    public static function matchingFully(array $cookieNames, $field, $value = true)
    {
        return new static($cookieNames, $field, $value);
    }

    /**
     * Create an operation to modify cookies with name substrings matching
     * $cookieSubstrs such that $field holds $value.
     *
     * @param array $cookieSubstrs
     * @param string $field
     * @param $value
     * @return Operation
     */
    public static function matchingPartially(array $cookieSubstrs, $field, $value = true)
    {
        $instance = new static($cookieSubstrs, $field, $value);
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

            if ( ! $cookieHeader->hasAttribute($this->field) and $this->isCandidateCookie($cookieName))
            {
                $cookieHeader->setAttribute($this->field, $this->value);
            }
        }
    }

    /**
     * Determine whether $cookieName is a candidate for modification by the
     * current Operation
     *
     * @param string $cookieName
     * @return bool
     */
    private function isCandidateCookie($cookieName)
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

    /**
     * Determine whether $cookieName is a candidate for modification by the
     * current Operation's internal substring list
     *
     * @param string $cookieName
     * @return bool
     */
    private function matchesSubstring($cookieName)
    {
        foreach ($this->cookieList as $forbidden)
        {
            if (strpos(strtolower($cookieName), $forbidden) !== false)
            {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine whether $cookieName is a candidate for modification by the
     * current Operation's internal cookie name list
     *
     * @param string $cookieName
     * @return bool
     */
    private function matchesFully($cookieName)
    {
        return in_array(
            strtolower($cookieName),
            $this->cookieList,
            true
        );
    }
}
