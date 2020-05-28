<?php

namespace IPS\brilliantdiscord;

/* To prevent PHP errors (extending class does not exist) revealing path */

use IPS\Patterns\Singleton;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

class _Behavior extends Singleton {
    public static $databaseTable = 'brilliantdiscord_behavior';

    public function __construct() {
        if (!isset(\IPS\Data\Store::i()->discord_behavior)) {
            $this->reload();
        } else {
            $this->data = \IPS\Data\Store::i()->discord_behavior;
        }
    }

    protected function reload() {
        $this->data = \IPS\Data\Store::i()->discord_behavior = iterator_to_array(\IPS\Db::i()->select(['key', 'value'], static::$databaseTable)->setKeyField('key')->setValueField('value'));
    }

    public function __set($k, $v) {
        $this->data[$k] = $v;
        \IPS\Db::i()->update(static::$databaseTable, ['value' => $v], ['`key`=?', $k]);
        \IPS\Data\Store::i()->discord_behavior = $this->data;
    }

    public function setMultiple($array) {
        foreach ($array as $k => $v) {
            if ($this->data[$k] != $v) {
                $this->data[$k] = $v;
                \IPS\Db::i()->update(static::$databaseTable, ['value' => $v], ['`key`=?', $k]);
            }
        }
        \IPS\Data\Store::i()->discord_behavior = $this->data;
    }

    public function resetToDefault($for = NULL) {
        $db = &\IPS\Db::i();
        $query = "UPDATE `{$db->prefix}brilliantdiscord_behavior` SET `value`=`default`";
        if ($for !== NULL) {
            $query .= "WHERE " . $db->in('key', $for);
        }
        \IPS\Db::i()->query("UPDATE `{$db->prefix}brilliantdiscord_behavior` SET `value`=`default`");
        $this->reload();
    }
}