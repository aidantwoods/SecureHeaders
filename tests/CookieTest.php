<?php

namespace Tests;

use Aidantwoods\SecureHeaders\Http\StringHttpAdapter;
use Aidantwoods\SecureHeaders\SecureHeaders;
use PHPUnit_Framework_TestCase;

class CookieTest extends PHPUnit_Framework_TestCase
{

    public function testCookieUpgrades()
    {
        $headerStrings = new StringHttpAdapter(array(
            'Set-Cookie: normalcookie=value1',
            'Set-Cookie: authcookie=value2',
        ));

        $headers = new SecureHeaders;
        $headers->errorReporting(false);

        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertContains('Set-Cookie: normalcookie=value1', $headersString);
        $this->assertContains('Set-Cookie: authcookie=value2; Secure; HttpOnly; SameSite=Lax', $headersString);
    }

    public function testSameSiteCookiesNoSameSite()
    {
        $headerStrings = new StringHttpAdapter(array(
            'Set-Cookie: authcookie=value'
        ));

        $headers = new SecureHeaders;
        $headers->errorReporting(false);

        $headers->auto(SecureHeaders::AUTO_ALL & ~SecureHeaders::AUTO_COOKIE_SAMESITE);

        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertNotContains('SameSite', $headersString);
    }

    public function testSameSiteCookiesStrictModeNoSameSite()
    {
        $headerStrings = new StringHttpAdapter(array(
            'Set-Cookie: authcookie=value'
        ));

        $headers = new SecureHeaders;
        $headers->errorReporting(false);

        $headers->auto(SecureHeaders::AUTO_ALL & ~SecureHeaders::AUTO_COOKIE_SAMESITE);

        $headers->strictMode();

        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertNotContains('SameSite', $headersString);
    }

    public function testSameSiteCookiesStrictMode()
    {
        $headerStrings = new StringHttpAdapter(array(
            'Set-Cookie: authcookie=value'
        ));

        $headers = new SecureHeaders;
        $headers->errorReporting(false);

        $headers->strictMode();

        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertContains('Set-Cookie: authcookie=value; Secure; HttpOnly; SameSite=Strict', $headersString);
    }

    public function testSameSiteCookiesStrictModeExplicitLax()
    {
        $headerStrings = new StringHttpAdapter(array(
            'Set-Cookie: authcookie=value'
        ));

        $headers = new SecureHeaders;
        $headers->errorReporting(false);

        $headers->sameSiteCookies('lax');
        $headers->strictMode();

        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertContains('Set-Cookie: authcookie=value; Secure; HttpOnly; SameSite=Lax', $headersString);
    }

    public function testSameSiteCookiesExplicitLax()
    {
        $headerStrings = new StringHttpAdapter(array(
            'Set-Cookie: authcookie=value'
        ));

        $headers = new SecureHeaders;
        $headers->errorReporting(false);

        $headers->sameSiteCookies('lax');

        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertContains('Set-Cookie: authcookie=value; Secure; HttpOnly; SameSite=Lax', $headersString);
    }

    public function testSameSiteCookiesExplicitStrict()
    {
        $headerStrings = new StringHttpAdapter(array(
            'Set-Cookie: authcookie=value'
        ));

        $headers = new SecureHeaders;
        $headers->errorReporting(false);

        $headers->sameSiteCookies('strict');

        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertContains('Set-Cookie: authcookie=value; Secure; HttpOnly; SameSite=Strict', $headersString);
    }

    public function testCookiesRemovable()
    {
        $headerStrings = new StringHttpAdapter(array(
            'Set-Cookie: authcookie=value',
            'Set-Cookie: regularcookie=value'
        ));

        $headers = new SecureHeaders;
        $headers->errorReporting(false);

        $headers->removeCookie('authcookie');
        $headers->removeCookie('regularcookie');

        $headers->apply($headerStrings);

        $headersString = $headerStrings->getSentHeaders();

        $this->assertNotContains('Set-Cookie: authcookie', $headersString);
        $this->assertNotContains('Set-Cookie: regularcookie', $headersString);
        $this->assertNotContains('Set-Cookie:', $headersString);
    }
}   
