<?php

namespace Aidantwoods\SecureHeaders;

interface Header
{
    public function __construct($name, $value = '');

    public function getName();

    public function getFriendlyName();

    public function is($name);

    public function getValue();

    public function setValue($newValue);

    public function getFirstAttributeName();

    public function getAttributeValue($name);

    public function hasAttribute($name);

    public function removeAttribute($name);

    public function ensureAttributeMaximum($name, $maxValue);

    public function setAttribute($name, $value = true);

    public function forEachAttribute($callback);

    public function __toString();
}
