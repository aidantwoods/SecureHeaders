<?php

namespace Aidantwoods\SecureHeaders\Http;

use Aidantwoods\SecureHeaders\HeaderBag;

class StringHttpAdapter implements HttpAdapter
{
    private $headers = [];

    /**
     * Create a HttpAdapter for output as a string, with initial headers
     * $initialHeaders, an array with each item a header string
     *
     * @api
     *
     * @param array $initialHeaders
     * @return void
     */
    public function __construct(array $initialHeaders = [])
    {
        $this->headers = $initialHeaders;
    }

    /**
     * Send the given headers, overwriting all previously send headers
     *
     * @api
     *
     * @param HeaderBag $headers
     * @return void
     */
    public function sendHeaders(HeaderBag $headers)
    {
        $this->headers = $headers->get();
    }

    /**
     * Retrieve the current list of already-sent (or planned-to-be-sent) headers
     *
     * @api
     *
     * @return HeaderBag
     */
    public function getHeaders()
    {
        return HeaderBag::fromHeaderLines($this->headers);
    }

    /**
     * @api
     *
     * @return string
     */
    public function getSentHeaders()
    {
        $compiledHeaders = [];

        foreach ($this->headers as $header)
        {
            $compiledHeaders[] = (string) $header;
        }

        return implode("\n", $compiledHeaders);
    }
}
