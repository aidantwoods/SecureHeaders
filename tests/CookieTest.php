<?php

namespace Aidantwoods\SecureHeaders\Tests;

use Aidantwoods\SecureHeaders\Http\StringHttpAdapter;
use Aidantwoods\SecureHeaders\SecureHeaders;
use PHPUnit\Framework\TestCase;

class CookieTest extends TestCase
{
    public function testCookieUpgrades()
    {
        $headerStrings = new StringHttpAdapter([
            'Set-Cookie: normalcookie=value1',
            'Set-Cookie: authcookie=value2',
        ]);

        $headers = new SecureHeaders;
        $headers->errorReporting(false);

        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertStringContainsString('Set-Cookie: normalcookie=value1', $headersString);
        $this->assertStringContainsString('Set-Cookie: authcookie=value2; Secure; HttpOnly; SameSite=Lax', $headersString);
    }

    public function testSameSiteCookiesNoSameSite()
    {
        $headerStrings = new StringHttpAdapter([
            'Set-Cookie: authcookie=value'
        ]);

        $headers = new SecureHeaders;
        $headers->errorReporting(false);

        $headers->auto(SecureHeaders::AUTO_ALL & ~SecureHeaders::AUTO_COOKIE_SAMESITE);

        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertStringNotContainsString('SameSite', $headersString);
    }

    public function testSameSiteCookiesStrictModeNoSameSite()
    {
        $headerStrings = new StringHttpAdapter([
            'Set-Cookie: authcookie=value'
        ]);

        $headers = new SecureHeaders;
        $headers->errorReporting(false);

        $headers->auto(SecureHeaders::AUTO_ALL & ~SecureHeaders::AUTO_COOKIE_SAMESITE);

        $headers->strictMode();

        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertStringNotContainsString('SameSite', $headersString);
    }

    public function testSameSiteCookiesStrictMode()
    {
        $headerStrings = new StringHttpAdapter([
            'Set-Cookie: authcookie=value'
        ]);

        $headers = new SecureHeaders;
        $headers->errorReporting(false);

        $headers->strictMode();

        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertStringContainsString('Set-Cookie: authcookie=value; Secure; HttpOnly; SameSite=Strict', $headersString);
    }

    public function testSameSiteCookiesStrictModeExplicitLax()
    {
        $headerStrings = new StringHttpAdapter([
            'Set-Cookie: authcookie=value'
        ]);

        $headers = new SecureHeaders;
        $headers->errorReporting(false);

        $headers->sameSiteCookies('lax');
        $headers->strictMode();

        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertStringContainsString('Set-Cookie: authcookie=value; Secure; HttpOnly; SameSite=Lax', $headersString);
    }

    public function testSameSiteCookiesExplicitLax()
    {
        $headerStrings = new StringHttpAdapter([
            'Set-Cookie: authcookie=value'
        ]);

        $headers = new SecureHeaders;
        $headers->errorReporting(false);

        $headers->sameSiteCookies('lax');

        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertStringContainsString('Set-Cookie: authcookie=value; Secure; HttpOnly; SameSite=Lax', $headersString);
    }

    public function testSameSiteCookiesExplicitStrict()
    {
        $headerStrings = new StringHttpAdapter([
            'Set-Cookie: authcookie=value'
        ]);

        $headers = new SecureHeaders;
        $headers->errorReporting(false);

        $headers->sameSiteCookies('strict');

        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertStringContainsString('Set-Cookie: authcookie=value; Secure; HttpOnly; SameSite=Strict', $headersString);
    }

    public function testCookiesRemovable()
    {
        $headerStrings = new StringHttpAdapter([
            'Set-Cookie: authcookie=value',
            'Set-Cookie: regularcookie=value'
        ]);

        $headers = new SecureHeaders;
        $headers->errorReporting(false);

        $headers->removeCookie('authcookie');
        $headers->removeCookie('regularcookie');

        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertStringNotContainsString('Set-Cookie: authcookie', $headersString);
        $this->assertStringNotContainsString('Set-Cookie: regularcookie', $headersString);
        $this->assertStringNotContainsString('Set-Cookie:', $headersString);
    }
}
