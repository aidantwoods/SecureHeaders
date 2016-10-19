<?php
class CustomSecureHeaders extends SecureHeaders{
    public function __construct()
    {
        # content headers
        $this->add_header('Content-type', 'text/html; charset=utf-8');

        # remove headers leaking server information
        $this->remove_header('Server');
        $this->remove_header('X-Powered-By');

        # security headers for all (HTTP and HTTPS) connections
        $this->add_header('X-Frame-Options', 'Deny');

        # redirect to www subdomain if not on localhost
        $this->www_if_not_localhost();

        # add a csp policy, as specified in $base, defined below
        $this->csp($this->base);
        $this->add_csp_reporting('https://report-uri.example.com/csp', 1);

        setcookie('sess1', 'secret');
        setcookie('preference', 'not a secret');
        setcookie('another-preference', 'not a secret', 10, '/', null, 1);

        # add a hpkp policy
        $this->hpkp(
            array(
                'pin1', 
                ['pin2', 'sha256'],
                ['sha256', 'pin3'],
                ['pin4']
            ),
            15,
            1
        );

        # use regular PHP function to add strict transport security
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');

        # enable safe-mode, which should auto-remove the above header
        # safe-mode will generate an error of level E_USER_NOTICE if it has to remove 
        # or modify any headers
        $this->safe_mode();

        # uncomment the next line to specifically allow HSTS in safe mode
        // $this->allow_in_safe_mode('Strict-Transport-Security');

    }

    public function www_if_not_localhost()
    {
        if ($_SERVER['SERVER_NAME'] !== 'localhost' and substr($_SERVER['HTTP_HOST'], 0, 4) !== 'www.')
        {
            $this->add_header('HTTP/1.1 301 Moved Permanently');
            $this->add_header('Location', 'https://www.'.$_SERVER['SERVER_NAME'].$_SERVER['REQUEST_URI']);
        }
    }

    private $base = array(
        "default-src" => ["'self'"],
        "script-src" => [
            "'self'",
            "https://www.google-analytics.com/"
        ],
        "style-src" => [
            "'self'",
            "https://fonts.googleapis.com/",
            "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/"
        ],
        "img-src" => [
            "'self'",
            "https://www.google-analytics.com/",
        ],
        "font-src" => [
            "'self'",
            "https://fonts.googleapis.com/",
            "https://fonts.gstatic.com/",
            "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/"
        ],
        "child-src" => [
            "'self'"
        ],
        "frame-src" => [
            "'self'"
        ],
        "base-uri" => ["'self'"],
        "connect-src" => [
            "'self'",
            "https://www.google-analytics.com/r/collect"
        ],
        "form-action" => [
            "'self'"
        ],
        "frame-ancestors" => ["'none'"],
        "object-src" => ["'none'"],
        'block-all-mixed-content' => [null]
    );
}
?>