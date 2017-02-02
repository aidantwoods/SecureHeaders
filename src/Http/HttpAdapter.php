<?php

namespace Aidantwoods\SecureHeaders\Http;

use Aidantwoods\SecureHeaders\HeaderBag;

interface HttpAdapter
{
    /**
     * Send the given headers, overwriting all previously sent headers.
     *
     * The HttpAdapter MUST delete headers before writing. Headers MUST be
     * added (and not replaced), such that if multiple headers with the same
     * name are contained within the HeaderBag, all MUST be sent.
     * (e.g. setting multiple cookies with multiple headers named 'Set-Cookie').
     *
     * The HttpAdapter MUST NOT attempt to place 'Set-Cookie' headers into a
     * cookie-jar (placing cookies into a cookie-jar will likely cause loss of
     * properties that are not yet implemeted by the cookie-jar, e.g. (at time
     * of writing) the `SameSite` cookie attribute).
     *
     * @param HeaderBag $headers
     * @return void
     */
    public function sendHeaders(HeaderBag $headers);

    /**
     * Retrieve the current list of already-sent (or planned-to-be-sent) headers
     *
     * @return HeaderBag
     */
    public function getHeaders();
}
