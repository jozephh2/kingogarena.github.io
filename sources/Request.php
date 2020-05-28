<?php

namespace IPS\brilliantdiscord;

/* To prevent PHP errors (extending class does not exist) revealing path */
if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

class _Request
{
    const API_URL = 'https://discordapp.com/api/v6/';
    /**
     * @var \IPS\Http\Request\Curl | \IPS\Http\Request\Sockets
     */
    protected $request;
    /**
     * @var \IPS\Http\Url
     */
    protected $url;
    public $endpoint;
    protected $authHeader = NULL;
    protected $headers = [];

    public $lastReqData = NULL;

    public static function successCodes() { return [200, 201, 204, 304]; }

    public function __construct($path, $queryString = []) {
        $this->endpoint = $path;
        $this->url = \IPS\Http\Url::external(static::API_URL . $path)->setQueryString($queryString);
        $this->request = $this->url->request();
    }

    public function bot($token = NULL) {
        if ($token == NULL) {
            if (\IPS\Settings::i()->brilliantdiscord_token) {
                $token = \IPS\Settings::i()->brilliantdiscord_token;
            } else {
                throw new \InvalidArgumentException("inconfigured");
            }
        }
        $this->authHeader = "Bot $token";
    }

    public function headers($array = NULL, $merge = TRUE) {
        if ($array == NULL) {
            return $this->headers;
        }
        if (!\is_array($this->headers)) {
            throw new \InvalidArgumentException;
        }
        if ($merge) {
            $this->headers = array_merge($this->headers, $array);
        } else {
            $this->headers = $array;
        }
        return $this->headers;
    }

    public function basic($user, $pass) {
        $this->authHeader = NULL;
        $this->request->login($user, $pass);
    }

    public function bearer($accessToken) {
        $this->authHeader = "Bearer $accessToken";
    }

    public function applyDefaultHeaders() {
        $this->headers([
            'Content-Type' => 'application/json',
            'User-Agent' => 'DiscordBot (BrilliantDiscordIntegration, v1)'
        ]);
    }

    /**
     * Make a request
     *
     * @param string $method
     * @param string|array|null $body
     * @return \IPS\Http\Response
     */
    public function submit($method = 'get', $body = NULL) {
        $this->lastReqData = $body;
        $headers = $this->headers;
        if ($this->authHeader != NULL) {
            $headers['Authorization'] = $this->authHeader;
        }
        $this->request->setHeaders($headers);
        $method = mb_strtolower($method);
        if ($method == 'head') {
            return $this->request->head();
        } else {
            return $this->request->$method($body);
        }
    }

    /**
     * Get URL
     *
     * @return \IPS\Http\Url
     */
    public function getUrl() {
        return $this->url;
    }

    /**
     * Get request
     *
     * @return \IPS\Http\Request\Curl|\IPS\Http\Request\Sockets
     */
    public function getRequest() {
        return $this->request;
    }

    //<editor-fold desc="Predefined Requests">
    public static function verifyToken($token) {
        $request = new static("oauth2/applications/@me");
        $request->bot($token);
        $request->applyDefaultHeaders();
        return $request;
    }
    //</editor-fold>
}