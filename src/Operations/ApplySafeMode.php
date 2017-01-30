<?php

namespace Aidantwoods\SecureHeaders\Operations;

use Aidantwoods\SecureHeaders\Header;
use Aidantwoods\SecureHeaders\HeaderBag;
use Aidantwoods\SecureHeaders\Operation;

class ApplySafeMode implements Operation
{
    private static $unsafeHeaders = array(
        'strict-transport-security' => 'sanitizeSTS',
        'public-key-pins' => 'sanitizePKP',
    );

    private $exceptions;

    public function __construct(array $exceptions = array())
    {
        $this->exceptions = $exceptions;
    }

    /**
     * Transform the given set of headers
     *
     * @param HeaderBag $headers
     * @return void
     */
    public function modify(HeaderBag &$headers)
    {
        foreach ($headers->get() as $header) {
            $headerName = $header->getName();

            $isUnsafe = array_key_exists($headerName, self::$unsafeHeaders);
            $hasException = array_key_exists($headerName, $this->exceptions);

            if ($isUnsafe && !$hasException) {
                $method = self::$unsafeHeaders[$headerName];

                $this->$method($header);
            }
        }
    }

    private function sanitizeSTS(Header $header)
    {
        $origValue = $header->getValue();

        // Only do these when the attribute exists!
        $header->ensureAttributeMaximum('max-age', 86400);
        $header->removeAttribute('includeSubDomains');
        $header->removeAttribute('preload');

        if ($header->getValue() !== $origValue) {
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
        $origValue = $header->getValue();

        // Only do these when the attributes exist
        $header->ensureAttributeMaximum('max-age', 10);
        $header->removeAttribute('includeSubDomains');

        if ($header->getValue() !== $origValue) {
            /*$this->warn(
                'Some HPKP settings were overridden because Safe-Mode is enabled.'
            );*/
        }
    }
}
