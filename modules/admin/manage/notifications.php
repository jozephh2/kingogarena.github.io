<?php


namespace IPS\brilliantdiscord\modules\admin\manage;

/* To prevent PHP errors (extending class does not exist) revealing path */

use IPS\brilliantdiscord\Notification;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

/**
 * notifications
 */
class _notifications extends \IPS\Node\Controller
{
	/**
	 * Node Class
	 */
	protected $nodeClass = '\IPS\brilliantdiscord\Notification';
	
	/**
	 * Execute
	 *
	 * @return	void
	 */
	public function execute()
	{
        \IPS\brilliantdiscord\Application::acpConfCheck(TRUE);
		\IPS\Dispatcher::i()->checkAcpPermission( 'brds_notifications_manage' );
		parent::execute();
	}

	public function conditions()
    {
        try {
            $node = Notification::load(\IPS\Request::i()->id);
            \IPS\Output::i()->title = \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_notifications_fcond_title', FALSE, [
                'sprintf' => $node->_title,
            ]);
        } catch (\OutOfRangeException $e) {
            \IPS\Output::i()->error('node_error', '2SBR108/1', 404, '');
            return;
        }

        if (!$node->canEdit()) {
            \IPS\Output::i()->error('node_noperm_edit', '2SBR108/2', 403, '');
        }

        $form = new \IPS\Helpers\Form;
        $node->conditionForm($form);
        $values = $form->values();
        if ($values = $form->values()) {
            if ($node->saveConditionForm($form, $values)) {
                \IPS\Output::i()->redirect(\IPS\Http\Url::internal('app=brilliantdiscord&module=manage&controller=notifications'), 'saved');
            }
        }
        \IPS\Output::i()->output = $form;
    }

    protected function _afterSave( \IPS\Node\Model $old = NULL, \IPS\Node\Model $new, $lastUsedTab = FALSE )
    {
        if ($old == NULL || $old->item_class != $new->item_class) {
            $new->conditions = NULL;
            $new->save();
            \IPS\Output::i()->redirect(\IPS\Http\Url::internal('app=brilliantdiscord&module=manage&controller=notifications&do=conditions')->setQueryString('id', $new->id));
        }
        parent::_afterSave($old, $new, $lastUsedTab);
    }
}