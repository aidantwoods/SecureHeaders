<?php

namespace Aidantwoods\SecureHeaders\Headers;

use InvalidArgumentException;
use Aidantwoods\SecureHeaders\Header;
use Aidantwoods\SecureHeaders\Util\Types;

abstract class AbstractHeader implements Header
{
    protected $name;
    protected $value;

    protected $attributes = [];

    /**
     * Create a header with name $name and value $value
     *
     * @param string $name
     * @param string $value
     */
    public function __construct($name, $value = '')
    {
        Types::assert(['string' => [$name, $value]]);

        $this->name = $name;
        $this->value = $value;

        $this->parseAttributes();
    }

    /**
     * {@inheritDoc}
     */
    public function getName()
    {
        return strtolower($this->name);
    }

    /**
     * {@inheritDoc}
     */
    public function getFriendlyName()
    {
        $friendlyHeader = str_replace('-', ' ', $this->getName());
        return ucwords($friendlyHeader);
    }

    /**
     * {@inheritDoc}
     */
    public function is($name)
    {
        Types::assert(['string' => [$name]]);

        return strtolower($name) === strtolower($this->name);
    }

    /**
     * {@inheritDoc}
     */
    public function getValue()
    {
        return $this->value;
    }

    /**
     * {@inheritDoc}
     */
    public function setValue($newValue)
    {
        $this->value = $newValue;

        $this->parseAttributes();
    }

    /**
     * {@inheritDoc}
     */
    public function getFirstAttributeName()
    {
        reset($this->attributes);

        return key($this->attributes);
    }

    /**
     * {@inheritDoc}
     */
    public function getAttributeValue($name)
    {
        Types::assert(['string' => [$name]]);

        if ( ! $this->hasAttribute($name))
        {
            throw new InvalidArgumentException(
                "Attribute '$name' was not found"
            );
        }

        return $this->attributes[strtolower($name)][0]['value'];
    }

    /**
     * {@inheritDoc}
     */
    public function hasAttribute($name)
    {
        Types::assert(['string' => [$name]]);

        $name = strtolower($name);

        return array_key_exists($name, $this->attributes);
    }

    /**
     * {@inheritDoc}
     */
    public function removeAttribute($name)
    {
        Types::assert(['string' => [$name]]);

        $name = strtolower($name);
        unset($this->attributes[$name]);

        $this->writeAttributesToValue();
    }

    /**
     * {@inheritDoc}
     */
    public function ensureAttributeMaximum($name, $maxValue)
    {
        Types::assert(['string' => [$name], 'int' => [$maxValue]]);

        if (isset($this->attributes[$name]))
        {
            foreach ($this->attributes[$name] as &$attribute)
            {
                if (intval($attribute['value']) > $maxValue)
                {
                    $attribute['value'] = $maxValue;
                }
            }

            $this->writeAttributesToValue();
        }
    }

    /**
     * {@inheritDoc}
     */
    public function setAttribute($name, $value = true)
    {
        Types::assert(['string' => [$name], 'int|bool|string' => [$value]]);

        $key = strtolower($name);

        $this->attributes[$key] = [
            [
                'name' => $name,
                'value' => $value
            ]
        ];

        if ($value === false)
        {
            unset($this->attributes[$key]);
        }

        $this->writeAttributesToValue();
    }

    /**
     * {@inheritDoc}
     */
    public function forEachAttribute(callable $callable)
    {
        foreach ($this->attributes as $attributes)
        {
            foreach ($attributes as $attribute)
            {
                $callable($attribute['name'], $attribute['value']);
            }
        }
    }

    /**
     * {@inheritDoc}
     */
    public function __toString()
    {
        return $this->name . ':' .($this->value === '' ? '' : ' ' . $this->value);
    }

    /**
     * Parse and store attributes from the internal header value
     *
     * @return void
     */
    protected function parseAttributes()
    {
        $parts = explode('; ', $this->value);

        $this->attributes = [];

        foreach ($parts as $part)
        {
            $attrParts = explode('=', $part, 2);

            $type = strtolower($attrParts[0]);

            if ( ! isset($this->attributes[$type]))
            {
                $this->attributes[$type] = [];
            }

            $this->attributes[$type][] = [
                'name' => $attrParts[0],
                'value' => isset($attrParts[1]) ? $attrParts[1] : true
            ];
        }
    }

    /**
     * Write internal attributes to the internal header value
     *
     * @return void
     */
    protected function writeAttributesToValue()
    {
        $attributeStrings = [];

        foreach ($this->attributes as $attributes)
        {
            foreach ($attributes as $attrInfo)
            {
                $key = $attrInfo['name'];
                $value = $attrInfo['value'];

                if ($value === true)
                {
                    $string = $key;
                }
                elseif ($value === false)
                {
                    continue;
                }
                else
                {
                    $string = "$key=$value";
                }

                $attributeStrings[] = $string;
            }
        }

        $this->value = implode('; ', $attributeStrings);
    }
}
