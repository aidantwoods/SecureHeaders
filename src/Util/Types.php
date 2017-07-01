<?php

namespace Aidantwoods\SecureHeaders\Util;

class Types
{
    /**
     * Assert that $typeList maps expected types to an array of that type.
     * The type NULL is permitted (assertion assumes types are nullable).
     *
     * Optionally provide $argNums as an ordered list of argument numbers to be
     * displayed in the exception message if arguments are recieved out of order,
     * not starting at one, or have gaps from what would be recieved in the
     * function's argument list ordering.
     *
     * @param array $typeList
     * @param array $argNums
     */
    public static function assert(array $typeList, array $argNums = null)
    {
        $i = 0;
        foreach ($typeList as $type => $vars)
        {
            $type = self::normalizeType($type);

            foreach ($vars as $var)
            {
                $allowedTypes = array_merge(
                    ['NULL'],
                    explode('|', $type)
                );

                if ( ! in_array(($varType = gettype($var)), $allowedTypes))
                {
                    if ( ! isset($argNums))
                    {
                        $argNums = self::generateArgNums($typeList);
                    }

                    throw TypeError::fromBacktrace($argNums[$i], $type, $varType);
                }

                $i++;
            }
        }
    }

    /**
     * Generate sequential argument numbers for $typeList.
     *
     * @param array $typeList
     * @return int[]
     */
    private static function generateArgNums(array $typeList)
    {
        $n = array_sum(array_map(
            function ($vars)
            {
                return count((array) $vars);
            },
            $typeList
        ));

        return range(1, $n);
    }

    /**
     * Normalise the given type name, $type.
     *
     * @param string $type
     * @return string
     */
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
