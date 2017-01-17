<?php

namespace Aidantwoods\SecureHeaders;

use Aidantwoods\SecureHeaders\Util\Types;

class HeaderBag
{
    protected $headers = array();

    public function __construct(array $headers = array())
    {
        // Send all headers through `add` to make sure they are properly lower-cased
        foreach ($headers as $name => $value)
        {
            $this->add($name, $value);
        }
    }

    public static function fromHeaderLines(array $lines)
    {
        $bag = new static;

        foreach ($lines as $line)
        {
            list($name, $value) = explode(': ', $line, 2);

            $bag->add($name, $value);
        }

        return $bag;
    }

    public function has($name)
    {
        Types::assert(array('string' => array($name)));

        return array_key_exists(strtolower($name), $this->headers);
    }

    public function add($name, $value = '')
    {
        Types::assert(array('string' => array($name, $value)));

        $key = strtolower($name);
        if ( ! array_key_exists($key, $this->headers)) $this->headers[$key] = array();

        $this->headers[$key][] = new Header($name, $value);
    }

    public function replace($name, $value = '')
    {
        Types::assert(array('string' => array($name, $value)));

        $header = new Header($name, $value);
        $this->headers[strtolower($name)] = array($header);
    }

    public function remove($name)
    {
        Types::assert(array('string' => array($name)));

        unset($this->headers[strtolower($name)]);
    }

    public function removeAll()
    {
        $this->headers = array();
    }

    public function get()
    {
        return array_reduce(
            $this->headers,
            function ($all, $item) {
                return array_merge($all, $item);
            },
            array()
        );
    }
}

class Header
{
    private $name;
    private $value;

    public function __construct($name, $value = '')
    {
        $this->name = $name;
        $this->value = $value;
    }

    public function getName()
    {
        return $this->name;
    }

    public function getValue()
    {
        return $this->value;
    }

    public function __toString()
    {
        return $this->name . ($this->value === '' ? '' : ': ' . $this->value);
    }
}
