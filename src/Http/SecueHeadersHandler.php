<?php

namespace Aidantwoods\SecureHeaders\Http;

use Aidantwoods\SecureHeaders\Http\Psr7Adapter;
use Aidantwoods\SecureHeaders\SecureHeaders;
use Psr\Http\Message\RequestInterface as Request;
use Psr\Http\Message\ResponseInterface as Response;

/**
 * Secure headers handler
 *
 * Middleware to apply Secure headers to a PSR7 response
 */
class SecureHeadersHandler
{
    /**
     * Headers
     *
     * @var SecureHeaders
     *
     * @access protected
     */
    protected $headers;

    /**
     * __construct
     *
     * @param SecureHeaders $headers Configured headers instance
     *
     * @access public
     */
    public function __construct(SecureHeaders $headers)
    {
        $this->headers = $headers;
    }

    /**
     * Handle PSR7 Request
     *
     * Delegates to middleware chain and applies secure headers to the returned
     * response object before returning it
     *
     * @param Request  $request  Incoming PSR7 request
     * @param Response $response PSR7 Response
     * @param callable $next     Delagate middleware
     *
     * @return Response
     *
     * @access public
     */
    public function __invoke(Request $request, Response $response, callable $next)
    {
        $response = $next($request, $response);
        $headers  = $this->headers;
        $adapter  = $this->adapt($response);

        $headers->apply($adapter);
        $response = $adapter->getFinalResponse();

        return $response;
    }

    /**
     * Adapt a PSR7 Response
     *
     * @param Response $response PSR7 Response
     *
     * @return Psr7Adapter;
     *
     * @access protected
     */
    protected function adapt(Response $response)
    {
        return new Psr7Adapter($response);
    }
}
