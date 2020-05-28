<?php

namespace IPS\brilliantdiscord\Maintenance;

/* To prevent PHP errors (extending class does not exist) revealing path */

use IPS\brilliantdiscord\Util\UnhandledDiscordException;
use IPS\Patterns\ActiveRecord;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

class _Log extends ActiveRecord {
    protected static $multitons = [];
    public static $databaseTable = 'brilliantdiscord_logs';

    public function setDefaultValues() {
        $this->time = time();
    }

    public static function log(\Exception $e) {
        $log = new static;
        $log->message = $e->getMessage();
        $log->code = $e->getCode();
        $log->member = \IPS\Member::loggedIn()->member_id ?: 0;
        $exception_data = [
            'class' => get_class( $e ),
            'line' => $e->getLine(),
            'file' => $e->getFile(),
            'trace' => $e->getTraceAsString(),
        ];
        if ($e instanceof UnhandledDiscordException) $exception_data['request_data'] = $e->requestData();
        $log->exception_data = $exception_data;
        $log->save();
    }

    public function get_exception_data() {
        return json_decode($this->_data['exception_data'] ?: "null", TRUE);
    }

    public function set_exception_data($value) {
        $this->_data['exception_data'] = json_encode($value);
    }
}