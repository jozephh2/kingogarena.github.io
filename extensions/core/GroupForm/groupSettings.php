<?php
/**
 * @brief		Admin CP Group Form
 * @author		<a href='https://www.invisioncommunity.com'>Invision Power Services, Inc.</a>
 * @copyright	(c) Invision Power Services, Inc.
 * @license		https://www.invisioncommunity.com/legal/standards/
 * @package		Invision Community
 * @subpackage	Brilliant Discord Integration
 * @since		25 Jan 2019
 */

namespace IPS\brilliantdiscord\extensions\core\GroupForm;

/* To prevent PHP errors (extending class does not exist) revealing path */
if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

/**
 * Admin CP Group Form
 */
class _groupSettings
{
	/**
	 * Process Form
	 *
	 * @param	\IPS\Helpers\Form		$form	The form
	 * @param	\IPS\Member\Group		$group	Existing Group
	 * @return	void
	 */
	public function process( &$form, $group )
	{
	    if (\IPS\Settings::i()->brilliantdiscord_configured_guild && $group->g_id != \IPS\Settings::i()->guest_group) {
            $p = 'brilliantdiscord_group_';
            $new = !((bool) $group->g_id);
            $form->add( new \IPS\Helpers\Form\YesNo( $p.'bypass_approval', $new ? FALSE : $group->discord_bypass_approval, FALSE ) );
            $form->add( new \IPS\Helpers\Form\Select( $p.'roles', $new ? [] : $group->discord_roles, FALSE, ['parse' => 'normal', 'multiple' => TRUE, 'options' => \IPS\brilliantdiscord\Util\Guild::roles()] ) );
        }
	}
	
	/**
	 * Save
	 *
	 * @param	array				$values	Values from form
	 * @param	\IPS\Member\Group	$group	The group
	 * @return	void
	 */
	public function save( $values, &$group )
	{
	    $p = 'brilliantdiscord_group_';
	    if (\IPS\Settings::i()->brilliantdiscord_configured_guild && $group->g_id != \IPS\Settings::i()->guest_group) {
	        $roles = $values[$p.'roles'];
	        if (\is_array($roles)) {
	            $roles = implode(",", $roles);
            }
	        $group->setDiscordData([
	            'discord_roles' => $roles,
                'bypass_approval' => $values[$p.'bypass_approval']
            ]);
        }
	}
}