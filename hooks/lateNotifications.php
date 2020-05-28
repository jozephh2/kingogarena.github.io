//<?php

/* To prevent PHP errors (extending class does not exist) revealing path */
if ( !\defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	exit;
}

abstract class brilliantdiscord_hook_lateNotifications extends _HOOK_CLASS_
{
    /**
     * Unhide
     *
     * @param	\IPS\Member|NULL|FALSE	$member	The member doing the action (NULL for currently logged in member, FALSE for no member)
     * @return	void
     */
    public function unhide( $member )
    {
	try
	{
	        $state = $this->hidden();
	        parent::unhide( $member );
	
	        if (!\in_array($state, [1, -3])) return;
	        \IPS\brilliantdiscord\Notification::parseContent(\get_called_class(), $this, TRUE);
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
