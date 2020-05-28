<?php


namespace IPS\brilliantdiscord\modules\admin\manage;

/* To prevent PHP errors (extending class does not exist) revealing path */

use IPS\brilliantdiscord\RateLimit\RateLimitedException;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

/**
 * behavior
 */
class _behavior extends \IPS\Dispatcher\Controller
{
	/**
	 * Execute
	 *
	 * @return	void
	 */
	public function execute()
	{
        \IPS\brilliantdiscord\Application::acpConfCheck(TRUE);
		\IPS\Dispatcher::i()->checkAcpPermission( 'brds_behavior_manage' );
		parent::execute();
	}

	/**
	 * ...
	 *
	 * @return	void
	 */
	protected function manage()
	{
		\IPS\Output::i()->title = \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_behavior');

		$form = new \IPS\Helpers\Form;
		$prefix = 'brilliantdiscord_behavior_form_';
		$prefix_len = mb_strlen($prefix);

		$form->addTab($prefix.'tab_general');

		try {
		    $roles = ['no_role' => ''];
		    foreach (\IPS\brilliantdiscord\Util\Guild::roles() as $k => $v) $roles[$k] = $v;
            $form->add( new \IPS\Helpers\Form\Select( $prefix.'basic_role', \IPS\brilliantdiscord\Behavior::i()->basic_role, TRUE, ['parse' => 'normal', 'options' => $roles], function($val) {
                if ($val == 'no_role') {
                    throw new \DomainException('form_required');
                }
            } ) );
        } catch (RateLimitedException $e) {
            $form->add( new \IPS\Helpers\Form\Select( $prefix.'basic_role', \IPS\brilliantdiscord\Behavior::i()->basic_role, TRUE, ['parse' => 'normal', 'options' => ['no_role' => '']], function($val) {
                if ($val == 'no_role') {
                    throw new \DomainException('form_required');
                }
            } ) );
            $form->elements[''][$prefix.'basic_role']->error = $e->ipsMessage();
        }

		$form->add( new \IPS\Helpers\Form\YesNo( $prefix.'enable_approval', \IPS\brilliantdiscord\Behavior::i()->enable_approval, FALSE ) );
		$form->add( new \IPS\Helpers\Form\YesNo( $prefix.'sync_nicknames', \IPS\brilliantdiscord\Behavior::i()->sync_nicknames, FALSE ) );

		if ($values = $form->values()) {
		    foreach ($values as $k => $v) {
		        if (mb_substr($k, 0, $prefix_len) == $prefix) {
		            unset($values[$k]);
		            $values[mb_substr($k, $prefix_len)] = $v;
		        }
            }
		    \IPS\brilliantdiscord\Behavior::i()->setMultiple($values);
        }
		\IPS\Output::i()->output = $form;
	}

	
	// Create new methods with the same name as the 'do' parameter which should execute it
}