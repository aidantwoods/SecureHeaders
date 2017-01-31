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
        $policies = array();

        foreach ($this->attributes as $attributes)
        {
            foreach ($attributes as $attrInfo)
            {
                $directive = $attrInfo['name'];
                $value = $attrInfo['value'];

                if ($value === true)
                {
                    $string = $directive;
                }
                elseif ( ! is_string($value) or trim($value) === '')
                {
                    continue;
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

    public function setAttribute($name, $value = true)
    {
        $key = strtolower($name);

        if ( ! isset($this->attributes[$key]))
        {
            $this->attributes[$key] = array();
        }

        $this->attributes[$key][] = array(
            'name' => $name,
            'value' => $value
        );

        $this->writeAttributesToValue();
    }
}
