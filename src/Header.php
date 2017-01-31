<?php

namespace Aidantwoods\SecureHeaders;

use InvalidArgumentException;
use Aidantwoods\SecureHeaders\Headers\RegularHeader;

class Header
{
    private static $subClasses = array(
        'content-security-policy'   => 'CSPHeader'
    );

    private $instance;

    public function __construct($name, $value = '')
    {
        foreach (self::$subClasses as $substring => $subClass)
        {
            if (strpos(strtolower($name), $substring) !== false)
            {
                $subClass = __NAMESPACE__."\\Headers\\$subClass";

                $this->instance = new $subClass($name, $value);

                break;
            }
        }

        if ( ! isset($this->instance))
        {
            $this->instance = new RegularHeader($name, $value);
        }
    }

    public function __call($method, $args) {
       return call_user_func_array(
           array(
               $this->instance,
               $method
            ),
           $args
        );
    }

    public function __toString()
    {
        return (string) $this->instance;
    }
}
