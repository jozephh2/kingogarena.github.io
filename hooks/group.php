//<?php

/* To prevent PHP errors (extending class does not exist) revealing path */
if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	exit;
}

class brilliantdiscord_hook_group extends _HOOK_CLASS_
{
    protected static $_discordGroupData = [];

    public function get_discord_roles() {
	try
	{
	        if (!$this->g_id) return [];
	        if (!isset(static::$_discordGroupData[$this->g_id])) $this->loadDiscordData();
	        if (!static::$_discordGroupData[$this->g_id]['discord_roles']) return [];
	        return explode(",", static::$_discordGroupData[$this->g_id]['discord_roles']);
	}
	catch ( \RuntimeException $e )
	{
		if ( method_exists( get_parent_class(), __FUNCTION__ ) )
		{
			return \call_user_func_array( 'parent::' . __FUNCTION__, \func_get_args() );
		}
		else
		{
			throw $e;
		}
	}
    }

    public function get_discord_bypass_approval() {
	try
	{
	        if (!$this->g_id) return FALSE;
	        if (!isset(static::$_discordGroupData[$this->g_id])) $this->loadDiscordData();
	        return (bool) static::$_discordGroupData[$this->g_id]['bypass_approval'];
	}
	catch ( \RuntimeException $e )
	{
		if ( method_exists( get_parent_class(), __FUNCTION__ ) )
		{
			return \call_user_func_array( 'parent::' . __FUNCTION__, \func_get_args() );
		}
		else
		{
			throw $e;
		}
	}
    }

    protected function loadDiscordData() {
	try
	{
	        if ($this->g_id == \IPS\Settings::i()->guest_group) {
	            static::$_discordGroupData[$this->g_id] = [];
	        }
	        try {
	            static::$_discordGroupData[$this->g_id] = \IPS\Db::i()->select('*', 'brilliantdiscord_groupdata', ['group_id=?', $this->g_id])->first();
	        } catch (\UnderflowException $e) {
	            static::$_discordGroupData[$this->g_id] = ['discord_roles' => '', 'bypass_approval' => FALSE, 'group_id' => $this->g_id];
	            \IPS\Db::i()->insert('brilliantdiscord_groupdata', static::$_discordGroupData[$this->g_id]);
	        }
	}
	catch ( \RuntimeException $e )
	{
		if ( method_exists( get_parent_class(), __FUNCTION__ ) )
		{
			return \call_user_func_array( 'parent::' . __FUNCTION__, \func_get_args() );
		}
		else
		{
			throw $e;
		}
	}
    }

    public function setDiscordData($data) {
	try
	{
	        if (!isset(static::$_discordGroupData[$this->g_id])) $this->loadDiscordData();
	        static::$_discordGroupData[$this->g_id] = $data;
	        \IPS\Db::i()->update('brilliantdiscord_groupdata', $data, ['group_id=?', $this->g_id]);
	}
	catch ( \RuntimeException $e )
	{
		if ( method_exists( get_parent_class(), __FUNCTION__ ) )
		{
			return \call_user_func_array( 'parent::' . __FUNCTION__, \func_get_args() );
		}
		else
		{
			throw $e;
		}
	}
    }

    public function delete() {
	try
	{
	        \IPS\Db::i()->delete('brilliantdiscord_groupdata', ['group_id=?', $this->g_id]);
	        parent::delete();
	}
	catch ( \RuntimeException $e )
	{
		if ( method_exists( get_parent_class(), __FUNCTION__ ) )
		{
			return \call_user_func_array( 'parent::' . __FUNCTION__, \func_get_args() );
		}
		else
		{
			throw $e;
		}
	}
    }
}
