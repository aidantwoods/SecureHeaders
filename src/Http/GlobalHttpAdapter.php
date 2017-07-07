<?php

namespace Aidantwoods\SecureHeaders\Http;

use Aidantwoods\SecureHeaders\HeaderBag;

class GlobalHttpAdapter implements HttpAdapter
{
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
        header_remove();

        foreach ($headers->get() as $header)
        {
            header(
                (string) $header,
                false
            );
        }
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
        return HeaderBag::fromHeaderLines(
            headers_list()
        );
    }
}
