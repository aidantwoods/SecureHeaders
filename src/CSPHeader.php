<?php

namespace Aidantwoods\SecureHeaders;

use InvalidArgumentException;
use Aidantwoods\SecureHeaders\Operations\CompileCSP;

class CSPHeader extends RegularHeader
{
    protected function parseAttributes()
    {
        $this->attributes = array();

        $policy = CompileCSP::deconstructCSP($this->value);

        foreach ($policy as $directive => $sources)
        {
            if ( ! isset($this->attributes[$directive]))
            {
                $this->attributes[$directive] = array();
            }

            $this->attributes[$directive][] = array(
                'name' => $directive,
                'value' => $sources === true ?: implode(' ', $sources)
            );
        }
    }

    protected function writeAttributesToValue()
    {
        $attributeStrings = array();

        foreach ($this->attributes as $attributes)
        {
            $policies = array();

            foreach ($attributes as $attrInfo)
            {
                $directive = $attrInfo['name'];
                $value = $attrInfo['value'];

                if ($value === true)
                {
                    $string = $directive;
                }
                else
                {
                    $string = "$directive $value";
                }

                $policy = CompileCSP::deconstructCSP($string);

                $policies[] = $policy;
            }
        }

        $policy = CompileCSP::mergeCSPList($policies);

        $this->value = CompileCSP::compile($policy);
    }
}
