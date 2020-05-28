<?php


namespace IPS\brilliantdiscord\modules\admin\manage;

/* To prevent PHP errors (extending class does not exist) revealing path */

use IPS\brilliantdiscord\Approval;
use IPS\brilliantdiscord\RateLimit\RateLimitedException;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

/**
 * memberManage
 */
class _memberManage extends \IPS\Dispatcher\Controller
{
    protected $member;
    protected $message;
    protected $redirect = TRUE;
	/**
	 * Execute
	 *
	 * @return	void
	 */
	public function execute()
	{
        \IPS\brilliantdiscord\Application::acpConfCheck(TRUE);
		\IPS\Dispatcher::i()->checkAcpPermission('member_edit', 'core', 'members');
		$this->member = \IPS\Member::load(\IPS\Request::i()->member);
        if (!$this->member->member_id) {
            \IPS\Output::i()->error('node_error', '2SBR102/1', 404);
        }
        if ($this->member->isAdmin()) {
            \IPS\Dispatcher::i()->checkAcpPermission('member_edit_admin', 'core', 'members');
        }
		parent::execute();
        if ($this->redirect) {
            \IPS\Output::i()->redirect(\IPS\Http\Url::internal('app=core&module=members&controller=members&do=view&id='.$this->member->member_id), $this->message ?: 'saved');
        }
	}

	/**
	 * ...
	 *
	 * @return	void
	 */
	protected function manage()
	{
		// This is the default method if no 'do' parameter is specified
	}

	protected function synchronize()
    {
        try {
            $this->member->discordSync();
            $this->message = 'brilliantdiscord_sync_success';
        } catch (RateLimitedException $e) {
            $this->message = $e->ipsMessage();
        } catch (\OutOfRangeException $e) {
            $this->message = 'brilliantdiscord_error_nosyncperm';
        }
    }

    protected function kick()
    {
        try {
            $this->member->discordKick();
            $this->message = 'brilliantdiscord_kick_success';
        } catch (RateLimitedException $e) {
            $this->message = $e->ipsMessage();
        } catch (\OutOfRangeException $e) {
            $this->message = 'brilliantdiscord_error_nosyncperm';
        }
    }

    protected function forceJoin()
    {
        try {
            list($request, $response) = $this->member->discordForceJoin();
            switch ($response->httpResponseCode) {
                case 204:
                    $this->message = 'brilliantdiscord_forcejoin_already_member';
                    break;
                case 201:
                    $this->message = 'brilliantdiscord_forcejoin_success';
                    break;
                case 403:
                    // User is banned
                    if ($response->decodeJson()['code'] == 40007) {
                        $this->message = 'brilliantdiscord_forcejoin_banned';
                        break;
                    }
                default:
                    (new \IPS\brilliantdiscord\Util\UnhandledDiscordException($request, $response))->safeHandle(TRUE, '4SBR102/2');
            }
        } catch (RateLimitedException $e) {
            $this->message = $e->ipsMessage();
        }
    }

    public function logs()
    {
        \IPS\Request::i()->mid = $this->member->member_id;
        (new approvalqueue)->info();
        $this->redirect = FALSE;
    }

    public function approve()
    {
        $this->member->discordAction(Approval::ACTION_APPROVE, \IPS\Member::loggedIn());
        $this->message = 'brilliantdiscord_success';
    }

    public function disapprove()
    {
        $this->member->discordAction(Approval::ACTION_DENY_MANUAL, \IPS\Member::loggedIn());
        $this->message = 'brilliantdiscord_success';
    }
	
	// Create new methods with the same name as the 'do' parameter which should execute it
}