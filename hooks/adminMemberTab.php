//<?php

/* To prevent PHP errors (extending class does not exist) revealing path */
if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	exit;
}

class brilliantdiscord_hook_adminMemberTab extends _HOOK_CLASS_
{
    public function leftColumnBlocks()
    {
	try
	{
	        $blocks = parent::leftColumnBlocks();
	        if (\IPS\Settings::i()->brilliantdiscord_configured_guild) {
	            $blocks[] = \IPS\brilliantdiscord\extensions\core\MemberACPProfileBlocks\discordMemberInfo::class;
	        }
	        return $blocks;
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
