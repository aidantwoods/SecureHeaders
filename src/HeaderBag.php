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
}

class Header
{
    private $name;
    private $value;

    private $attributes = array();

    public function __construct($name, $value = '')
    {
        $this->name = $name;
        $this->value = $value;

        $this->parseAttributes();
    }

    public function getName()
    {
        return strtolower($this->name);
    }

    public function is($name)
    {
        return strtolower($name) === strtolower($this->name);
    }

    public function getValue()
    {
        return $this->value;
    }

    public function setValue($newValue)
    {
        $this->value = $newValue;

        $this->parseAttributes();
    }

    public function getFirstAttributeName()
    {
        reset($this->attributes);

        return key($this->attributes);
    }

    public function removeAttribute($name)
    {
        $name = strtolower($name);
        unset($this->attributes[$name]);

        $this->writeAttributesToValue();
    }

    public function ensureAttributeMaximum($name, $maxValue)
    {
        if (isset($this->attributes[$name])) {
            foreach ($this->attributes[$name] as &$attribute) {
                if (intval($attribute['value']) > $maxValue) {
                    $attribute['value'] = $maxValue;
                }
            }

            $this->writeAttributesToValue();
        }
    }

    public function enableAttribute($name)
    {
        $key = strtolower($name);

        $this->attributes[$key] = array(
            array(
                'name' => $name,
                'value' => true
            )
        );

        $this->writeAttributesToValue();
    }

    public function __toString()
    {
        return $this->name . ':' .(empty($this->value) ? '' : ' ' . $this->value);
    }

    private function parseAttributes()
    {
        $parts = explode('; ', $this->value);

        $this->attributes = array();
        foreach ($parts as $part) {
            $attrParts = explode('=', $part, 2);

            $type = strtolower($attrParts[0]);

            if ( ! isset($this->attributes[$type])) {
                $this->attributes[$type] = array();
            }

            $this->attributes[$type][] = array(
                'name' => $attrParts[0],
                'value' => isset($attrParts[1]) ? $attrParts[1] : true
            );
        }
    }

    private function writeAttributesToValue()
    {
        $attributeStrings = array();
        foreach ($this->attributes as $attributes) {
            foreach ($attributes as $attrInfo) {
                $key = $attrInfo['name'];
                $value = $attrInfo['value'];

                if ($value === true) {
                    $string = $key;
                } else if ($value === false) {
                    continue;
                } else {
                    $string = "$key=$value";
                }

                $attributeStrings[] = $string;
            }
        }

        $this->value = implode('; ', $attributeStrings);
    }
}
