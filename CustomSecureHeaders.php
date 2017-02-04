<?php
class CustomSecureHeaders extends SecureHeaders
{
    public function __construct()
    {
        # implicitly call $this->done() on first byte of output
        $this->doneOnOutput();

        # content headers
        $this->header('Content-type', 'text/html; charset=utf-8');

        # Custom function added in this extenstion:
        # redirect to www subdomain if not on localhost
        $this->www_if_not_localhost();

        # add a csp policy, as specified in $base, defined below
        $this->csp($this->base);

        $this->cspNonce('style');
        $this->cspNonce('script');

        # whitelist a css snippet in the style-src directive
        $style = 'body {background: black;}';
        $this->cspHash('style', $style);

        # add csp reporting
        $this->csp(
            'report', 'https://report-uri.example.com/csp',
            'script', 'http://my.cdn.org'
        );

        # add some cookies
        setcookie('auth1', 'not a secret');
        setcookie('sId', 'secret');
        $this->protectedCookie('auth', self::COOKIE_SUBSTR | self::CCOOKIE_REMOVE);

        setcookie('sess1', 'secret');
        setcookie('notasessioncookie', 'not a secret');
        $this->protectedCookie('sess', self::COOKIE_SUBSTR | self::CCOOKIE_REMOVE);
        $this->protectedCookie('sess1', self::COOKIE_NAME);

        setcookie('preference', 'not a secret');
        setcookie('another-preference', 'not a secret', 10, '/', null, true, false);

        # add a hpkp policy
        $this->hpkp(
            array(
                'pin1',
                array('pin2', 'sha256'),
                array('sha256', 'pin3'),
                array('pin4')
            ),
            1500,
            1
        );

        # use regular PHP function to add strict transport security
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');

        # enable safe-mode, which should auto-modify the above header
        # safe-mode will generate an error of level E_USER_NOTICE if it has to modify any headers
        $this->safeMode();

        # uncomment the next line to allow HSTS in safe mode
        // $this->safeModeException('Strict-Transport-Security');
    }

    public function www_if_not_localhost()
    {
        if ($_SERVER['SERVER_NAME'] !== 'localhost' and substr($_SERVER['HTTP_HOST'], 0, 4) !== 'www.') {
            $this->header('HTTP/1.1 301 Moved Permanently');
            $this->header('Location', 'https://www.'.$_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI']);
        }
    }

    private $base = array(
        "default-src" => array("'self'"),
        "script-src" => array(
            "'self'",
            "https://www.google-analytics.com/"
        ),
        "style-src" => array(
            "'self'",
            "https://fonts.googleapis.com/",
            "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/"
        ),
        "img-src" => array(
            "'self'",
            "https://www.google-analytics.com/",
        ),
        "font-src" => array(
            "'self'",
            "https://fonts.googleapis.com/",
            "https://fonts.gstatic.com/",
            "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/"
        ),
        "child-src" => array(
            "'self'"
        ),
        "frame-src" => array(
            "'self'"
        ),
        "base-uri" => array("'self'"),
        "connect-src" => array(
            "'self'",
            "https://www.google-analytics.com/r/collect"
        ),
        "form-action" => array(
            "'self'"
        ),
        "frame-ancestors" => array("'none'"),
        "object-src" => array("'none'"),
        'block-all-mixed-content' => array(null)
    );
}
