<?php

namespace Aidantwoods\SecureHeaders\Http;

use Aidantwoods\SecureHeaders\HeaderBag;

class StringHttpAdapter implements HttpAdapter
{
    private $headers = [];
    private $initialHeaders;

    public function __construct(array $initialHeaders = [])
    {
        $this->initialHeaders = $initialHeaders;
    }

    /**
     * Send the given headers, overwriting all previously send headers
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
     * @return HeaderBag
     */
    public function getHeaders()
    {
        return HeaderBag::fromHeaderLines($this->initialHeaders);
    }

    public function getSentHeaders()
    {
        $compiledHeaders = [];

        foreach ($this->headers as $header) {
            $compiledHeaders[] = (string) $header;
        }

        return implode(PHP_EOL, $compiledHeaders);
    }
}
