<?php
/**
 * @brief		Member Sync
 * @author		<a href='https://www.invisioncommunity.com'>Invision Power Services, Inc.</a>
 * @copyright	(c) Invision Power Services, Inc.
 * @license		https://www.invisioncommunity.com/legal/standards/
 * @package		Invision Community
 * @subpackage	Brilliant Discord Integration
 * @since		31 Jan 2019
 */

namespace IPS\brilliantdiscord\extensions\core\MemberSync;

/* To prevent PHP errors (extending class does not exist) revealing path */

use IPS\brilliantdiscord\RateLimit\RateLimitedException;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

/**
 * Member Sync
 */
class _memberSync
{
	/**
	 * Member account has been created
	 *
	 * @param	$member	\IPS\Member	New member account
	 * @return	void
	 */
	public function onCreateAccount( $member )
	{

	}
	
	/**
	 * Member has validated
	 *
	 * @param	\IPS\Member	$member		Member validated
	 * @return	void
	 */
	public function onValidate( $member )
	{
	
	}
	
	/**
	 * Member has logged on
	 *
	 * @param	\IPS\Member	$member		Member that logged in
	 * @return	void
	 */
	public function onLogin( $member )
	{

	}
	
	/**
	 * Member has logged out
	 *
	 * @param	\IPS\Member		$member			Member that logged out
	 * @param	\IPS\Http\Url	$returnUrl	    The URL to send the user back to
	 * @return	void
	 */
	public function onLogout( $member, $returnUrl )
	{
	
	}
	
	/**
	 * Member account has been updated
	 *
	 * @param	$member		\IPS\Member	Member updating profile
	 * @param	$changes	array		The changes
	 * @return	void
	 */
	public function onProfileUpdate( $member, $changes )
	{
	    if ($this->_configured(TRUE) && (isset($changes['member_group_id']) || isset($changes['mgroup_others']) || isset($changes['name']))) {
	        try {
	            $member->discordSync();
            } catch (RateLimitedException $e) {  // It will be synchronized later.
	        } catch (\OutOfRangeException  $e) {} // Probably no permission to edit the member.
        }
	}
	
	/**
	 * Member is flagged as spammer
	 *
	 * @param	$member	\IPS\Member	The member
	 * @return	void
	 */
	public function onSetAsSpammer( $member )
	{
		if ($this->_configured(TRUE)) $member->discordKick();
	}
	
	/**
	 * Member is unflagged as spammer
	 *
	 * @param	$member	\IPS\Member	The member
	 * @return	void
	 */
	public function onUnSetAsSpammer( $member )
	{
		
	}
	
	/**
	 * Member is merged with another member
	 *
	 * @param	\IPS\Member	$member		Member being kept
	 * @param	\IPS\Member	$member2	Member being removed
	 * @return	void
	 */
	public function onMerge( $member, $member2 )
	{
        \IPS\Db::i()->update(\IPS\brilliantdiscord\Approval::$databaseTable, ['member' => $member->member_id], ['`target_member`=? AND `type`=?', $member2->member_id, \IPS\brilliantdiscord\Approval::ACTION_REQUEST]);
	    \IPS\Db::i()->update(\IPS\brilliantdiscord\Approval::$databaseTable, ['target_member' => $member->member_id], ['`target_member`=?', $member2->member_id]);
	}
	
	/**
	 * Member is deleted
	 *
	 * @param	$member	\IPS\Member	The member
	 * @return	void
	 */
	public function onDelete( $member )
	{
	    if ($this->_configured(TRUE)) $member->discordKick();
	    // Delete approval logs
	    \IPS\Db::i()->delete(\IPS\brilliantdiscord\Approval::$databaseTable, ['target_member=?', $member->member_id]);
	}

	/**
	 * Email address is changed
	 *
	 * @param	\IPS\Member	$member	The member
	 * @param 	string		$new	New email address
	 * @param 	string		$old	Old email address
	 * @return	void
	 */
	public function onEmailChange( $member, $new, $old )
	{

	}

	/**
	 * Password is changed
	 *
	 * @param	\IPS\Member	$member	The member
	 * @param 	string		$new	New password
	 * @return	void
	 */
	public function onPassChange( $member, $new )
	{

	}

	protected function _configured($guild)
    {
	    return \IPS\Settings::i()->brilliantdiscord_configured && (\IPS\Settings::i()->brilliantdiscord_configured_guild || !$guild);
    }
}