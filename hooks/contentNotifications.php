//<?php

/* To prevent PHP errors (extending class does not exist) revealing path */
if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	exit;
}

abstract class brilliantdiscord_hook_contentNotifications extends _HOOK_CLASS_
{
    /**
     * Process created object AFTER the object has been created
     *
     * @param	\IPS\Content\Comment|NULL	$comment	The first comment
     * @param	array						$values		Values from form
     * @return	void
     */
    protected function processAfterCreate( $comment, $values )
    {
	try
	{
	        parent::processAfterCreate($comment, $values);
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
