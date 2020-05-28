<?php

namespace IPS\brilliantdiscord\Util;

/* To prevent PHP errors (extending class does not exist) revealing path */

use Throwable;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

// todo To throw or not to throw - that's the question...
class _UnhandledDiscordException extends \RuntimeException
{
    /**
     * @var \IPS\brilliantdiscord\Request
     */
    public $request;
    /**
     * @var \IPS\Http\Response
     */
    public $response;


    /**
     * _UnhandledDiscordException constructor.
     *
     * @param $request
     * @param $response
     */
    public function __construct(\IPS\brilliantdiscord\Request $request, \IPS\Http\Response $response)
    {
        $this->request = $request;
        $this->response = $response;
        $endpoint = mb_substr((string)$request->getUrl(), mb_strlen(\IPS\brilliantdiscord\Request::API_URL));
        parent::__construct("Unexpected response code at /{$endpoint}", $response->httpResponseCode, null);
    }

    public function requestData()
    {
        return ['content' => $this->response->content, 'req_head' => $this->request->headers(), 'res_head' => $this->response->httpHeaders, 'req_data' => $this->request->lastReqData];
    }

    public function safeHandle($displayErrorPage = TRUE, $errorPageCode = '4SBR000/2')
    {
        if ( \IPS\IN_DEV ) {
            throw $this;
        }
        // Log it
        \IPS\brilliantdiscord\Maintenance\Log::log( $this );
        if ($displayErrorPage) {
            \IPS\Output::i()->error('generic_error', $errorPageCode, 500);
        }
    }
}