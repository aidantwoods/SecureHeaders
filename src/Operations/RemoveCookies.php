<?php

namespace Aidantwoods\SecureHeaders\Operations;

use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Operation;

class RemoveCookies implements Operation
{
    private $removedCookies;

    public function __construct(array $removedCookies)
    {
        $this->removedCookies = $removedCookies;
    }

    /**
     * Transform the given set of headers
     *
     * @param HeaderBag $headers
     * @return void
     */
    public function modify(HeaderBag &$headers)
    {
        $cookies = $headers->getByName('set-cookie');

        $headers->remove('set-cookie');

        foreach ($cookies as $key => $cookie)
        {
            $cookieName = $cookie->getFirstAttributeName();

            if ( ! in_array(strtolower($cookieName), $this->removedCookies))
            {
                $headers->add('Set-Cookie', $cookie->getValue());
            }
        }
    }
}
