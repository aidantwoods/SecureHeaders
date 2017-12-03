<?php

namespace Aidantwoods\SecureHeaders;

use Aidantwoods\SecureHeaders\Util\Types;

class HeaderBag
{
    protected $headers = [];

    /**
     * Create a HeaderBag containing the headers, $headers.
     *
     * @api
     *
     * @param array<string, string> $headers
     */
    public function __construct(array $headers = [])
    {
        # Send all headers through `add` to make sure they are properly
        # lower-cased
        foreach ($headers as $name => $value)
        {
            $this->add($name, $value);
        }
    }

    /**
     * Create a HeaderBag from an array of header lines, $lines.
     *
     * @api
     *
     * @param string[] $lines
     * @return static
     */
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

    /**
     * Determine whether the HeaderBag contains a header with $name,
     * case-insensitively.
     *
     * @api
     *
     * @param string $name
     * @return bool
     */
    public function has($name)
    {
        Types::assert(['string' => [$name]]);

        return array_key_exists(strtolower($name), $this->headers);
    }

    /**
     * Add a header with $name and value $value
     *
     * @api
     *
     * @param string $name
     * @param string $value
     * @return void
     */
    public function add($name, $value = '')
    {
        Types::assert(['string' => [$name, $value]]);

        $key = strtolower($name);
        if ( ! array_key_exists($key, $this->headers))
        {
            $this->headers[$key] = [];
        }

        $this->headers[$key][] = HeaderFactory::build($name, $value);
    }

    /**
     * Add (in replace mode) a header with $name and value $value
     *
     * @api
     *
     * @param string $name
     * @param string $value
     * @return void
     */
    public function replace($name, $value = '')
    {
        Types::assert(['string' => [$name, $value]]);

        $header = HeaderFactory::build($name, $value);
        $this->headers[strtolower($name)] = [$header];
    }

    /**
     * Remove header(s) with $name
     *
     * @api
     *
     * @param string $name
     * @return void
     */
    public function remove($name)
    {
        Types::assert(['string' => [$name]]);

        unset($this->headers[strtolower($name)]);
    }

    /**
     * Remove all headers from the HeaderBag.
     *
     * @api
     *
     * @return void
     */
    public function removeAll()
    {
        $this->headers = [];
    }

    /**
     * Get all Headers from the HeaderBag
     *
     * @api
     *
     * @return Header[]
     */
    public function get()
    {
        return array_reduce(
            $this->headers,
            function ($all, $item)
            {
                return array_merge($all, $item);
            },
            []
        );
    }

    /**
     * Get Headers from the HeaderBag with name, $name
     *
     * @api
     *
     * @param string $name
     * @return Header[]
     */
    public function getByName($name)
    {
        Types::assert(['string' => [$name]]);

        $name = strtolower($name);

        if ( ! array_key_exists($name, $this->headers))
        {
            return [];
        }

        return $this->headers[$name];
    }

    /**
     * Let a header named $name be $header.
     * Apply $callable($header) to every header named $name.
     *
     * @api
     *
     * @param string $name
     * @param callable $callable
     * @return void
     */
    public function forEachNamed($name, callable $callable)
    {
        Types::assert(['string' => [$name]]);

        $name = strtolower($name);

        if (isset($this->headers[$name]))
        {
            foreach ($this->headers[$name] as $header)
            {
                $callable($header);
            }
        }
    }
}
