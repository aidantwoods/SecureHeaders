<?php

namespace Aidantwoods\SecureHeaders;

interface Header
{
    /**
     * Get the header name
     *
     * @return string
     */
    public function getName();

    /**
     * Get the friendly header name (dashes replaced by spaces,
     * uppercase words)
     *
     * @return string
     */
    public function getFriendlyName();

    /**
     * Compare the given $name with the header name case insensitively
     *
     * @param string $name
     *
     * @return bool
     */
    public function is($name);

    /**
     * Get the value of the header
     *
     * @return ?string
     */
    public function getValue();

    /**
     * Set the value of the header, and reparse attribues to reflect this
     * new value
     *
     * @param string $newValue
     */
    public function setValue($newValue);

    /**
     * Get the first attribute's name from the header value
     *
     * @return ?string
     */
    public function getFirstAttributeName();

    /**
     * Get value of the attribute $name (if exists)
     *
     * @param string $name
     *
     * @return int|bool|string
     */
    public function getAttributeValue($name);

    /**
     * Return true if there is a case insensitive match for $name amoung the
     * header value's attributes
     *
     * @param string $name
     *
     * @return bool
     */
    public function hasAttribute($name);

    /**
     * Remove all attributes matching $name case insensitively from the header
     * value
     *
     * @param string $name
     */
    public function removeAttribute($name);

    /**
     * Enforce that the header value attribute matching $name case
     * insensitively does not exceed $maxValue. Rewrite the value of $name to
     * $maxValue if the current value exceeds this limit.
     *
     * @param string $name
     * @param int $maxValue
     */
    public function ensureAttributeMaximum($name, $maxValue);

    /**
     * Set the header attribute matching $name case insensitively to $value
     * removing multiple values if they exist. Make sure to implement
     * $value=false as appropriate for the particular header
     *
     * @param string $name
     * @param int|bool|string $value
     */
    public function setAttribute($name, $value = true);

    /**
     * Apply the given callback $callback($attributeName, $attributeValue)
     * to each attribute for each value
     *
     * @param callback $callback
     */
    public function forEachAttribute($callback);

    /**
     * Return the header string as appropriate for use in a HTTP response
     *
     * @return string
     */
    public function __toString();
}
