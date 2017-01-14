<?php

namespace Aidantwoods\SecureHeaders;

class HeaderBag
{
    protected $headers = array();

    public function __construct(array $headers = array())
    {
        // Send all headers through `replace` to make sure they are properly lower-cased
        foreach ($headers as $name => $value)
        {
            $this->replace($name, $value);
        }
    }

    public static function fromHeaderLines(array $lines)
    {
        $headers = array();

        foreach ($lines as $line)
        {
            list($name, $value) = explode(': ', $line, 2);

            $headers[$name] = $value;
        }

        return new static($headers);
    }

    public function has($name)
    {
        return array_key_exists(strtolower($name), $this->headers);
    }

    public function add($name, $value = '')
    {
        if ($this->has($name))
        {
            return;
        }

        $this->replace($name, $value);
    }

    public function replace($name, $value = '')
    {
        $this->headers[strtolower($name)] = $value;
    }

    public function remove($name)
    {
        unset($this->headers[strtolower($name)]);
    }

    public function removeAll()
    {
        $this->headers = array();
    }

    public function get()
    {
        return $this->headers;
    }
}
