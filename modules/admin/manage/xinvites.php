<?php


namespace IPS\brilliantdiscord\modules\admin\manage;

/* To prevent PHP errors (extending class does not exist) revealing path */
if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

/**
 * xinvites
 */
class _xinvites extends \IPS\Node\Controller
{
    /**
     * Node Class
     */
    protected $nodeClass = '\IPS\brilliantdiscord\Invite';

	/**
	 * Execute
	 *
	 * @return	void
	 */
	public function execute()
	{
        \IPS\brilliantdiscord\Application::acpConfCheck(TRUE);
		\IPS\Dispatcher::i()->checkAcpPermission( 'brds_xinvites_manage' );
		parent::execute();
	}
	
	// Create new methods with the same name as the 'do' parameter which should execute it
}