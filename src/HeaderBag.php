<?php

namespace Aidantwoods\SecureHeaders;

use Aidantwoods\SecureHeaders\Util\Types;

class HeaderBag
{
    protected $headers = array();

    public function __construct(array $headers = array())
    {
        # Send all headers through `add` to make sure they are properly
        # lower-cased
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
            preg_match('/^([^:]++)(?|(?:[:][ ]?+)(.*+)|())/', $line, $matches);
            array_shift($matches);

            list($name, $value) = $matches;

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

    /**
     * @return Header[]
     */
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

    public function getByName($name)
    {
        $name = strtolower($name);

        if( ! array_key_exists($name, $this->headers))
        {
            return array();
        }

        return $this->headers[$name];
    }

    public function forEachNamed($type, $callback)
    {
        $type = strtolower($type);

        if (isset($this->headers[$type])) {
            foreach ($this->headers[$type] as $header) {
                $callback($header);
            }
        }
    }
}
