<?php

namespace Aidantwoods\SecureHeaders\Operations;

use Aidantwoods\SecureHeaders\Header;
use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Operation;

class ApplySafeMode implements Operation
{
    const UNSAFE_HEADERS = array(
        'strict-transport-security' => 'sanitizeSTS',
        'public-key-pins' => 'sanitizePKP',
    );

    private $exceptions;

    public function __construct(array $exceptions)
    {
        $this->exceptions = $exceptions;
    }

    /**
     * Transform the given set of headers
     *
     * @param HeaderBag $headers
     * @return void
     */
    public function modify(HeaderBag $headers)
    {
        foreach ($headers->get() as $header) {
            $headerName = $header->getName();

            $isUnsafe = array_key_exists($headerName, self::UNSAFE_HEADERS);
            $hasException = array_key_exists($headerName, $this->exceptions);

            if ($isUnsafe && !$hasException) {
                $method = self::UNSAFE_HEADERS[$headerName];

                $this->$method($header);
            }
        }
    }

    private function sanitizeSTS(Header $header)
    {
        $origAttributes = $attributes = $header->getValueAsAttributes();

        // Only do these when the attribute exists!
        $attributes = $this->ensureAttributeIsMax($attributes, 'max-age', 86400);
        $attributes = $this->ensureAttributeEquals($attributes, 'includesubdomains', false);
        $attributes = $this->ensureAttributeEquals($attributes, 'preload', false);

        if ($attributes !== $origAttributes) {
            $header->setValueFromAttributes($attributes);

            /*$this->warn(
                'HSTS settings were overridden because Safe-Mode is enabled.
                <a href="
                https://scotthelme.co.uk/death-by-copy-paste/#hstsandpreloading">
                Read about</a> some common mistakes when setting HSTS via
                copy/paste, and ensure you
                <a href="
                https://www.owasp.org/index.php/
                HTTP_Strict_Transport_Security_Cheat_Sheet">
                understand the details</a> and possible side effects of this
                security feature before using it.'
            );*/
        }
    }

    private function sanitizePKP(Header $header)
    {
        $origAttributes = $attributes = $header->getValueAsAttributes();

        // Only do these when the attributes exist
        $attributes = $this->ensureAttributeIsMax($attributes, 'max-age', 10);
        $attributes = $this->ensureAttributeEquals($attributes, 'includesubdomains', false);

        if ($attributes !== $origAttributes) {
            $header->setValueFromAttributes($attributes);

            /*$this->warn(
                'Some HPKP settings were overridden because Safe-Mode is enabled.'
            );*/
        }
    }

    private function ensureAttributeIsMax($attributes, $key, $maxValue)
    {
        if (isset($attributes[$key])) {
            if (intval($attributes[$key]) > $maxValue) {
                $attributes[$key] = $maxValue;
            }
        }

        return $attributes;
    }

    private function ensureAttributeEquals($attributes, $key, $value)
    {
        if (isset($attributes[$key])) {
            $attributes[$key] = $value;
        }

        return $attributes;
    }
}
