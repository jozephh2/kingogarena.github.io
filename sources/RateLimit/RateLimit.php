<?php

namespace IPS\brilliantdiscord;

/* To prevent PHP errors (extending class does not exist) revealing path */

use IPS\brilliantdiscord\Util\VoidArray;
use IPS\Patterns\ActiveRecord;
use IPS\brilliantdiscord\RateLimit\RateLimitedException;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

class _RateLimit extends ActiveRecord
{
    const GLOBAL_ENDPOINT = '__global__';

    protected static $multitons = [];
    public static $databaseTable = 'brilliantdiscord_ratelimits';

    // todo too dirty :/
    public static function init()
    {
        // We don't want to cache ratelimits.
        static::$multitons = new VoidArray;
    }

    /**
     * Load Record
     *
     * @see		\IPS\Db::build
     * @param	int|string	$id					ID
     * @param	string		$idField			The database column that the $id parameter pertains to (NULL will use static::$databaseColumnId)
     * @param	mixed		$extraWhereClause	Additional where clause(s) (see \IPS\Db::build for details) - if used will cause multiton store to be skipped and a query always ran
     * @return	static
     * @throws	\InvalidArgumentException
     * @throws	\OutOfRangeException
     */
    public static function load( $id, $idField=NULL, $extraWhereClause=NULL )
    {
        if( $idField === NULL )
        {
            $idField = static::$databasePrefix . static::$databaseColumnId;
        }
        try
        {
            return static::constructFromData( static::constructLoadQuery( $id, $idField, $extraWhereClause )->first() );
        }
        catch ( \UnderflowException $e )
        {
            throw new \OutOfRangeException;
        }
    }

    public static function endpoint($endpoint, $major_param = NULL, $identifier = NULL)
    {
        try {
            return static::constructFromData(\IPS\Db::i()->select('*', static::$databaseTable, ['endpoint=? AND major_param=? AND identifier=?', $endpoint, $major_param, $identifier ?: \IPS\Settings::i()->brilliantdiscord_cid])->first());
        } catch (\UnderflowException $e) {
            $new = new static;
            $new->endpoint = $endpoint;
            $new->major_param = $major_param;
            $new->identifier = $identifier ?: \IPS\Settings::i()->brilliantdiscord_cid;
            return $new;
        }
    }

    public static function globalEndpoint($identifier = NULL)
    {
        return static::endpoint(static::GLOBAL_ENDPOINT, NULL, $identifier);
    }

    public function __clone()
    {
        throw new \BadMethodCallException;
    }

    public function isAvailable()
    {
        return $this->_new || $this->remaining > 0 || time() > $this->reset_time;
    }

    /**
     * Parses response & returns rate limit information
     *
     * @param \IPS\Http\Response $response
     * @param string $endpoint Endpoint
     * @param string $majorParam Major parameter in URL
     * @param string $identifier Client identifier
     * @return array
     */
    public static function parseResponse($response, $endpoint, $majorParam=NULL, $identifier=NULL)
    {
        $identifier = $identifier ?: \IPS\Settings::i()->brilliantdiscord_cid;
        $return = [];
        $save = FALSE;
        if ($response->httpResponseCode == 429) {
            $return['exceeded'] = TRUE;
            $json = $response->decodeJson();
            if ($json['global']) {
                $return['global'] = TRUE;
            } else {
                $return['global'] = FALSE;
            }
            $return['retryAfter'] = $json['retry_after'];
            $save = TRUE;
        } else {
            $return['exceeded'] = FALSE;
            if ($return['isLimited'] = isset($response->httpHeaders['x-ratelimit-reset'])) {
                $return['remaining'] = $response->httpHeaders['x-ratelimit-remaining'];
                $return['limit'] = $response->httpHeaders['x-ratelimit-limit'];
                $return['reset'] = $response->httpHeaders['x-ratelimit-reset'];
                $save = TRUE;
            }
            $return['global'] = FALSE;
        }
        if ($save) {
            $endpoint = $return['global'] ? static::globalEndpoint($identifier) : static::endpoint($endpoint, $majorParam, $identifier);
            if ($return['exceeded']) {
                $endpoint->remaining = 0;
                $endpoint->reset_time = time() + $return['retryAfter'];
            } else {
                $endpoint->remaining = $return['remaining'];
                $endpoint->limit = $return['limit'];
                $endpoint->reset_time = $return['reset'];
            }
           if (!$return['global']) $endpoint->major_param = $majorParam;
           $endpoint->save();
        }
        return $return;
    }

    public static function limitHandle($endpoint, $major_param, $callback, $identifier = NULL) {
        $rateLimit = static::endpoint($endpoint, $major_param, $identifier);
        $globalEndpoint = static::globalEndpoint($identifier);
        $mainAvailable = $rateLimit->isAvailable();
        $globalAvailable = $globalEndpoint->isAvailable();
        if ($globalAvailable) {
            if ($mainAvailable) {
                return $callback(function($response) use ($endpoint, $major_param, $identifier) {
                    $rateLimitResult = static::parseResponse($response, $endpoint, $major_param, $identifier);
                    if ($rateLimitResult['exceeded']) {
                        $exception = new RateLimitedException;
                        $exception->is_global = $rateLimitResult['global'];
                        $exception->reset_time = time() + $rateLimitResult['retry_after'];
                        $exception->identifier = $identifier;
                        throw $exception;
                    }
                    return $rateLimitResult;
                });
            } else {
                $exception = new RateLimitedException;
                $exception->is_global = false;
                $exception->reset_time = $rateLimit->reset_time;
                $exception->identifier = $identifier;
                throw $exception;
            }
        } else {
            $exception = new RateLimitedException;
            $exception->is_global = true;
            $exception->reset_time = $globalEndpoint->reset_time;
            $exception->identifier = $identifier;
            throw $exception;
        }
    }

    public static function clearRatelimits($identifier = NULL) {
        \IPS\Db::i()->delete(static::$databaseTable, $identifier === NULL ? NULL : ['`identifier`=?', $identifier]);
    }
}

_RateLimit::init();