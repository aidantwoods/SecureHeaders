<?php

namespace Aidantwoods\SecureHeaders\Util;

class Types
{
    public static function assert(array $typeList, array $argNums = null)
    {
        $i = 0;
        foreach ($typeList as $type => $vars) {
            $type = self::normalizeType($type);

            foreach ($vars as $var) {
                $allowedTypes = array_merge(
                    ['NULL'],
                    explode('|', $type)
                );

                if (! in_array(($varType = gettype($var)), $allowedTypes)) {
                    if (! isset($argNums)) {
                        $argNums = self::generateArgNums($typeList);
                    }

                    throw TypeError::fromBacktrace($argNums[$i], $type, $varType);
                }

                $i++;
            }
        }
    }

    private static function generateArgNums(array $typeList)
    {
        $n = array_sum(array_map(
            function ($vars) {
                return count((array) $vars);
            },
            $typeList
        ));

        return range(1, $n);
    }

    private static function normalizeType($type)
    {
        return preg_replace(
            [
                '/bool(?=$|[\|])/',
                '/int(?=$|[\|])/'
            ],
            [
                'boolean',
                'integer'
            ],
            strtolower($type)
        );
    }
}
