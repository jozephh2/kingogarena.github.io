<?php

namespace IPS\brilliantdiscord\Util;

/* To prevent PHP errors (extending class does not exist) revealing path */
if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

class _VoidArray implements \ArrayAccess
{
    public function offsetExists($offset)
    {
        return FALSE;
    }

    public function offsetGet($offset)
    {
        return NULL;
    }

    public function offsetSet($offset, $value)
    {
    }

    public function offsetUnset($offset)
    {
    }
}