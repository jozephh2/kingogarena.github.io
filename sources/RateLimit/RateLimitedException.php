<?php
namespace IPS\brilliantdiscord\RateLimit;

/* To prevent PHP errors (extending class does not exist) revealing path */
if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

class _RateLimitedException extends \LogicException {
    public $is_global;
    public $reset_time;
    public $identifier;

    public function ipsMessage() {
        $l = \IPS\Member::loggedIn()->language();
        return $l->addToStack('brilliantdiscord_rate_limited' . ($this->is_global ? '_global' : ''), FALSE,
            ['sprintf' => $this->timeLeft()]
        );
    }

    public function timeLeft() {
        $l = \IPS\Member::loggedIn()->language();
        $dateInterval = \IPS\DateTime::ts(time())->diff(\IPS\DateTime::ts($this->reset_time), TRUE);
        $seconds = \IPS\DateTime::ts(0)->add($dateInterval)->getTimestamp();
        return $seconds < 60 ?
            $l->addToStack( 'f_seconds', FALSE, [ 'pluralize' => [ $seconds ] ] )
            : \IPS\DateTime::formatInterval($dateInterval);
    }
}