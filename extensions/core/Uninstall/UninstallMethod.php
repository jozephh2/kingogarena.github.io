<?php
/**
 * @brief		Uninstall callback
 * @author		<a href='https://www.invisioncommunity.com'>Invision Power Services, Inc.</a>
 * @copyright	(c) Invision Power Services, Inc.
 * @license		https://www.invisioncommunity.com/legal/standards/
 * @package		Invision Community
 * @subpackage	Brilliant Discord Integration
 * @since		16 Feb 2019
 */

namespace IPS\brilliantdiscord\extensions\core\Uninstall;

/* To prevent PHP errors (extending class does not exist) revealing path */
if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

/**
 * Uninstall callback
 */
class _UninstallMethod
{
	/**
	 * Code to execute before the application has been uninstalled
	 *
	 * @param	string	$application	Application directory
	 * @return	array
	 */
	public function preUninstall( $application )
	{
	}

	/**
	 * Code to execute after the application has been uninstalled
	 *
	 * @param	string	$application	Application directory
	 * @return	array
	 */
	public function postUninstall( $application )
	{
	    $id = \IPS\Login\Handler::findMethod(\IPS\brilliantdiscord\LoginHandler::class)->id;
        \IPS\Lang::saveCustom( 'core', "login_method_{$id}", 'Discord' );
	    \IPS\Db::i()->delete('core_login_methods', ['login_classname=?', 'IPS\brilliantdiscord\LoginHandler']);
	}

	/**
	 * Code to execute when other applications are uninstalled
	 *
	 * @param	string	$application	Application directory
	 * @return	void
	 * @deprecated	This is here for backwards-compatibility - all new code should go in onOtherUninstall
	 */
	public function onOtherAppUninstall( $application )
	{
		return $this->onOtherUninstall( $application );
	}

	/**
	 * Code to execute when other applications or plugins are uninstalled
	 *
	 * @param	string	$application	Application directory
	 * @param	int		$plugin			Plugin ID
	 * @return	void
	 */
	public function onOtherUninstall( $application=NULL, $plugin=NULL )
	{
	}
}