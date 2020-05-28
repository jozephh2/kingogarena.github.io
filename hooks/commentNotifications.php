//<?php

/* To prevent PHP errors (extending class does not exist) revealing path */
if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	exit;
}

abstract class brilliantdiscord_hook_commentNotifications extends _HOOK_CLASS_
{
    public function postCreate()
    {
	try
	{
	        parent::postCreate();
	        \IPS\brilliantdiscord\Notification::parseContent(\get_called_class(), $this);
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
