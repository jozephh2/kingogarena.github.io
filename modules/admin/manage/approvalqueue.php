<?php
namespace IPS\brilliantdiscord\modules\admin\manage;

/* To prevent PHP errors (extending class does not exist) revealing path */

use IPS\brilliantdiscord\Approval;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

/**
 * approvalqueue
 */
class _approvalqueue extends \IPS\Dispatcher\Controller
{
	/**
	 * Execute
	 *
	 * @return	void
	 */
	public function execute()
	{
	    \IPS\brilliantdiscord\Application::acpConfCheck(TRUE);
	    if (!\IPS\brilliantdiscord\Behavior::i()->enable_approval) {
            \IPS\Output::i()->error('brilliantdiscord_error_approval_disabled', '1SBR103/7', 400);
        }
        \IPS\Dispatcher::i()->checkAcpPermission('brds_aprqueue_manage');
		parent::execute();
	}

	/**
	 * ...
	 *
	 * @return	void
	 */
	protected function manage()
	{
	    $data = Approval::waitingMembers();
	    $table = new \IPS\Helpers\Table\Custom($data, \IPS\Http\Url::internal('app=brilliantdiscord&module=manage&controller=approvalqueue'));

        $table->include = ['target_member', 'timestamp'];
        $table->mainColumn = 'target_member';
        $table->langPrefix = 'brilliantdiscord_aprqueue_';

        $table->tableTemplate = [\IPS\Theme::i()->getTemplate('tables', 'core', 'admin'), 'table'];
        $table->rowsTemplate = [\IPS\Theme::i()->getTemplate('tables', 'core', 'admin'), 'rows'];
        $table->noSort = ['target_member'];

        $table->rowButtons = function ($row) {
            $return = [];

            $return['accept'] = [
                'icon' => 'check',
                'title' => 'brilliantdiscord_aprqueue_accept',
                'data' => ['ipsDialog' => '', 'ipsDialog-title' => \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_aprqueue_accept')],
                'link' => \IPS\Http\Url::internal( 'app=brilliantdiscord&module=manage&controller=approvalqueue&do=doAction&action=1&mid=' . $row['target_member'] ),
            ];
            $return['deny'] = [
                'icon' => 'times-circle',
                'title' => 'brilliantdiscord_aprqueue_deny',
                'data' => ['ipsDialog' => '', 'ipsDialog-title' => \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_aprqueue_deny')],
                'link' => \IPS\Http\Url::internal( 'app=brilliantdiscord&module=manage&controller=approvalqueue&do=doAction&action=3&mid=' . $row['target_member'] ),
            ];
            $return['approve'] = [
                'icon' => 'check-circle',
                'title' => 'brilliantdiscord_aprqueue_approve',
                'data' => ['ipsDialog' => '', 'ipsDialog-title' => \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_aprqueue_approve')],
                'link' => \IPS\Http\Url::internal( 'app=brilliantdiscord&module=manage&controller=approvalqueue&do=doAction&action=2&mid=' . $row['target_member'] ),
            ];
            $return['logs'] = [
                'icon' => 'info-circle',
                'title' => 'brilliantdiscord_aprqueue_info',
                'data' => ['ipsDialog' => '', 'ipsDialog-title' => \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_aprqueue_info')],
                'link' => \IPS\Http\Url::internal( 'app=brilliantdiscord&module=manage&controller=approvalqueue&do=info&mid=' . $row['target_member'] ),
            ];

            return $return;
        };

        $table->parsers = [
            'timestamp' => function ($val, $row) {
                $t = \IPS\DateTime::ts($val);
                return $t->localeDate() . " " . $t->localeTime();
            },
            'target_member' => function ($val) {
                return \IPS\Theme::i()->getTemplate( 'configuration', 'brilliantdiscord')->approvalMemberDisplay(\IPS\Member::load($val), function($v) {
                    return \IPS\Http\Url::internal('app=core&module=members&controller=members&do=view&id='.$v);
                });
            }
        ];

        /*\IPS\Output::i()->sidebar['actions'] = [
            'prune' => [
                'icon' => 'trash-o',
                'title' => 'brilliantdiscord_logs_prune',
                'data' => ['ipsDialog' => '', 'ipsDialog-title' => \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_logs_prune')],
                'link' => \IPS\Http\Url::internal('app=brilliantdiscord&module=manage&controller=logs&do=prune')
            ],
            'export' => [
                'icon' => 'download',
                'title' => 'brilliantdiscord_logs_export',
                'data' => ['ipsDialog' => '', 'ipsDialog-title' => \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_logs_export')],
                'link' => \IPS\Http\Url::internal('app=brilliantdiscord&module=manage&controller=logs&do=export')
            ],
        ]; */

        /* Default sort options */
        $table->sortBy = $table->sortBy ?: 'time';
        $table->sortDirection = $table->sortDirection ?: 'desc';

        \IPS\Output::i()->title = \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_aprqueue');
        \IPS\Output::i()->output = $table;
	}

	public function info($url = NULL)
    {
        if ($mid = \IPS\Request::i()->mid) {
            try {
                $member = \IPS\Member::load($mid);
                if (!$member->member_id) \IPS\Output::i()->error('node_error', '2SBR103/1', 400);
                $table = new \IPS\Helpers\Table\Custom(Approval::logs($member), \IPS\Http\Url::internal('app=brilliantdiscord&module=manage&controller=approvalqueue&&do=info&mid='.$mid));
                $table->include = ['type', 'member', 'timestamp'];
                $table->mainColumn = 'type';
                $table->langPrefix = 'brilliantdiscord_aprqueue_logs_';

                $table->tableTemplate = [\IPS\Theme::i()->getTemplate('tables', 'core', 'admin'), 'table'];
                $table->rowsTemplate = [\IPS\Theme::i()->getTemplate('tables', 'core', 'admin'), 'rows'];
                $table->noSort = ['type', 'member'];

                $table->parsers = [
                    'type' => function ($val, $row) {
                        $key = NULL;
                        switch ($val) {
                            case Approval::ACTION_REQUEST: // Requested an approval
                                $key = 'requested';
                                break;
                            case Approval::ACTION_ACCEPT:
                                $key = 'accepted';
                                break;
                            case Approval::ACTION_APPROVE:
                                $key = 'accepted_lifetime';
                                break;
                            case Approval::ACTION_DENY:
                                $key = 'request_denied';
                                break;
                            case Approval::ACTION_DENY_MANUAL:
                                $key = 'denied';
                                break;
                            case Approval::ACTION_GIVE_ACCESS_LIFETIME:
                                $key = 'given_access_lifetime';
                                break;
                        }
                        return \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_aprqueue_action_type_' . $key);
                    },
                    'timestamp' => function ($val, $row) {
                        $t = \IPS\DateTime::ts($val);
                        return $t->localeDate() . " " . $t->localeTime();
                    },
                    'member' => function ($val) {
                        $url = \IPS\Http\Url::internal('app=core&module=members&controller=members&do=view&id='.$val);
                        $name = \IPS\Member::load($val)->name;
                        return "<a href='$url'>$name</a>";
                    }
                ];

                \IPS\Output::i()->output = "<div class='ipsPad'>$table</div>";
            } catch ( \UnderflowException $e ) {
                \IPS\Output::i()->error('node_error', '2SBR103/2', 400);
            }
        } else {
            \IPS\Output::i()->error('node_error', '2SBR103/3', 400);
        }
    }

    public function doAction()
    {
        if ($action = \IPS\Request::i()->action) {
            if ($mid = \IPS\Request::i()->mid) {
                $member = \IPS\Member::load($mid);
                if (!$member->member_id) \IPS\Output::i()->error('node_error', '2SBR103/4', 400);
                if (!$member->members_disable_pm) {
                    // Now we can prepare form.
                    $p = 'brilliantdiscord_aprqueue_action_form_';
                    $form = new \IPS\Helpers\Form;
                    $form->add( new \IPS\Helpers\Form\YesNo($p.'send_message', FALSE, FALSE, ['togglesOn' => [$mid.$action.'msg_title', $mid.$action.'leave', $mid.$action.'msg_content']]));
                    $form->add( new \IPS\Helpers\Form\YesNo($p.'auto_leave', TRUE, FALSE, [], NULL, NULL, NULL, $mid.$action.'leave'));
                    $form->add( new \IPS\Helpers\Form\Text($p.'msg_title', NULL, NULL, [], NULL, NULL, NULL, $mid.$action.'msg_title'));
                    $form->add( new \IPS\Helpers\Form\Editor($p.'msg_content', NULL, NULL, [
                        'app' => 'brilliantdiscord',
                        'key' => 'SendActionMessage',
                        'autoSaveKey' => "aprqueue-action-$mid-$action",
                    ], NULL, NULL, NULL, $mid.$action.'msg_content' ));
                    if ($values = $form->values()) {
                        if ($values[$p.'send_message']) {
                            $title = $values[$p.'msg_title'];
                            if (!$title) {
                                $form->elements[''][$p.'msg_title']->error = 'form_required';
                                \IPS\Output::i()->output = $form;
                                return;
                            }
                            $content = $values[$p.'msg_content'];
                            $item = \IPS\core\Messenger\Conversation
                                ::createItem(
                                    \IPS\Member::loggedIn(),
                                    \IPS\Request::i()->ipAddress(),
                                    \IPS\DateTime::create(),
                                    NULL
                                );
                            $item->title = $title;
                            $item->to_count	= 1;
                            $item->save();

                            // First message
                            $commentClass = $item::$commentClass;
                            $post = $commentClass::create(
                                $item, $content, TRUE, NULL, NULL,
                                \IPS\Member::loggedIn(), \IPS\DateTime::create()
                            );

                            $item->first_msg_id = $post->id;
                            $item->save();

                            $leave = $values[$p.'auto_leave'];
                            $item->authorize($leave ? $member : [\IPS\Member::loggedIn(), $member]);
                            $post->sendNotifications();
                        }
                        \IPS\Request::i()->setClearAutosaveCookie("aprqueue-action-$mid-$action");
                    } else {
                        \IPS\Output::i()->output = $form;
                        return;
                    }
                }
                // Now we can do action.
                $member->discordAction($action, \IPS\Member::loggedIn());
                \IPS\Output::i()->redirect(\IPS\Http\Url::internal('app=brilliantdiscord&module=manage&controller=approvalqueue'), 'brilliantdiscord_success');
            } else {
                \IPS\Output::i()->error('node_error', '2SBR103/5', 400);
            }
        } else {
            \IPS\Output::i()->error('node_error', '2SBR103/6', 400);
        }
    }
}