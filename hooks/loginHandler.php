//<?php

/* To prevent PHP errors (extending class does not exist) revealing path */
if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	exit;
}

abstract class brilliantdiscord_hook_loginHandler extends _HOOK_CLASS_
{
    public static function handlerClasses()
    {
	try
	{
	        $return = parent::handlerClasses();
	        $return[] = 'IPS\brilliantdiscord\LoginHandler';
	        return $return;
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
