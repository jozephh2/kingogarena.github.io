<?php


namespace IPS\brilliantdiscord\modules\front\xinvites;

/* To prevent PHP errors (extending class does not exist) revealing path */

use IPS\brilliantdiscord\Approval;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

/**
 * invite
 */
class _invite extends \IPS\Dispatcher\Controller
{
    /**
     * @var \IPS\brilliantdiscord\Invite
     */
    protected $invite;

    /**
	 * Execute
	 *
	 * @return	void
	 */
	public function execute()
	{
        if (!\IPS\Settings::i()->brilliantdiscord_configured_guild) \IPS\Output::i()->error( 'page_not_found', '2SBR100/1', 404 );
        if ($code = \IPS\Request::i()->icode) {
            try {
                $this->invite = \IPS\brilliantdiscord\Invite::constructFromData(\IPS\Db::i()->select('*', \IPS\brilliantdiscord\Invite::$databaseTable, ['code=?', $code])->first());
            } catch ( \UnderflowException $e ) {
                \IPS\Output::i()->error('node_error', '2SBR100/2', 404 );
            }
        } else {
            \IPS\Output::i()->error('node_error', '2SBR100/2', 404 );
        }
        \IPS\Output::i()->breadcrumb = [
            [ null, \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_invites') ],
            [ $this->invite->url(), $code]
        ];
		parent::execute();
	}

	/**
	 * ...
	 *
	 * @return	void
	 */
	protected function manage()
	{
	    \IPS\Output::i()->title = \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_invite');
        \IPS\Output::i()->metaTags['robots'] = 'noindex';
        \IPS\Output::i()->sidebar['enabled'] = FALSE;
        \IPS\Output::i()->bodyClasses[] = 'ipsLayout_minimal';
        \IPS\Output::i()->cssFiles = array_merge( \IPS\Output::i()->cssFiles, \IPS\Theme::i()->css( 'global/invite.css', 'brilliantdiscord' ) );
        $loginUrl = \IPS\Http\Url::internal( "app=core&module=system&controller=login", 'front', 'login' )->setQueryString( 'ref', (string) \IPS\Request::i()->url() );
        $registerUrl = \IPS\Http\Url::internal( "app=core&module=system&controller=register", 'front', 'register' )->setQueryString( 'ref', (string) \IPS\Request::i()->url() );
        $approvalNeeded = \IPS\Member::loggedIn()->discordApprovalNeeded($this->invite);
        \IPS\Output::i()->output = \IPS\Theme::i()->getTemplate('invites', 'brilliantdiscord')->accept(
            $this->invite,
            \IPS\Http\Url::internal('app=brilliantdiscord&module=xinvites&controller=invite&do=accept&icode=' . $this->invite->code, 'front', 'invite_accept'),
            \IPS\Login\Handler::findMethod('IPS\brilliantdiscord\LoginHandler'),
            \IPS\brilliantdiscord\Util\Guild::guildData(),
            $loginUrl,
            $registerUrl,
            $approvalNeeded && Approval::access(\IPS\Member::loggedIn()) == Approval::NO_ACCESS,
            $approvalNeeded && Approval::access(\IPS\Member::loggedIn()) == Approval::ACCESS_REQUESTED
        );
	}

	protected function accept()
    {
        \IPS\Session::i()->csrfCheck();
        if (!\IPS\Member::loggedIn() || !$this->invite->canView()) \IPS\Output::i()->error('node_error', '2SBR100/7', 401 );
        if (Approval::access(\IPS\Member::loggedIn()) == Approval::ACCESS_REQUESTED) \IPS\Output::i()->redirect($this->invite->url());
        /** @var \IPS\brilliantdiscord\LoginHandler $method */
        $method = \IPS\Login\Handler::findMethod('IPS\brilliantdiscord\LoginHandler');
        $link = $method->link(\IPS\Member::loggedIn());
        // If not reauthorized yet, check user's account and reauthorize if needed
        if (!isset($_SESSION['discord_reauthorized'])) {
            if ($link == NULL) {
                $this->reauthorize();
            } else {
                try {
                    $method->userProfileName(\IPS\Member::loggedIn());
                } catch (\IPS\Login\Exception $e) {
                    $this->reauthorize();
                }
            }
        } else {
            unset($_SESSION['discord_reauthorized']);
            // That's impossible (probably)
            if ($link == NULL) {
                \IPS\Output::i()->error('generic_error', '5SBR100/3', 500);
            }
        }
        try {
            if (\IPS\Member::loggedIn()->discordApprovalNeeded($this->invite) && Approval::access(\IPS\Member::loggedIn()) == Approval::NO_ACCESS) {
                \IPS\Member::loggedIn()->discordAction(Approval::ACTION_REQUEST, \IPS\Member::loggedIn());
                \IPS\Output::i()->redirect(\IPS\Http\Url::internal(''), 'brilliantdiscord_invite_approval_requested');
            }
            list($request, $response) = \IPS\Member::loggedIn()->discordForceJoin();
            switch ($response->httpResponseCode) {
                case 204:
                    \IPS\Output::i()->redirect(\IPS\Http\Url::internal(''), 'brilliantdiscord_invite_already_member');
                    break;
                case 201:
                    \IPS\Output::i()->redirect(\IPS\Http\Url::internal(''), 'brilliantdiscord_invite_success');
                    break;
                case 403:
                    // User is banned
                    if ($response->decodeJson()['code'] == 40007) {
                        \IPS\Output::i()->error('brilliantdiscord_invite_banned', '1SBR100/4', 401);
                    }
                default:
                    (new \IPS\brilliantdiscord\Util\UnhandledDiscordException($request, $response))->safeHandle(TRUE, '4SBR100/6');
            }
        } catch (\IPS\brilliantdiscord\RateLimit\RateLimitedException $e) {
            \IPS\Output::i()->error($e->ipsMessage(), '1SBR000/1', 429);
        }
    }

	protected function reauthorize()
    {
        // CSRF check is redundant here when using &do=accept
        if (\IPS\Request::i()->do == 'reauthorize') \IPS\Session::i()->csrfCheck();
        /**
         * @var \IPS\brilliantdiscord\LoginHandler $handler
         */
        // Prevent errors after refreshing (authorization code can't be used anymore)
        if ($_SESSION['triedBefore']) {
            \IPS\Request::i()->code = NULL;
            \IPS\Request::i()->error = NULL;
            unset($_SESSION['triedBefore']);
        }
        $handler = \IPS\Login\Handler::findMethod('IPS\brilliantdiscord\LoginHandler');
        $login = new \IPS\Login(\IPS\Http\Url::internal('app=brilliantdiscord&module=xinvites&controller=invite&do=reauthorize')->csrf()->setQueryString('icode', $this->invite->code), $handler->link() ?  \IPS\Login::LOGIN_REAUTHENTICATE : \IPS\Login::LOGIN_UCP);
        $login->reauthenticateAs = \IPS\Member::loggedIn();
        try {
            if (isset(\IPS\Request::i()->_processLogin)) {
                $_SESSION['triedBefore'] = TRUE;
            }
            $handler->authenticateButton($login);
        } catch ( \IPS\Login\Exception $e ) {
            if ($e->getCode() == \IPS\Login\Exception::MERGE_SOCIAL_ACCOUNT) {
                if ($e->member->member_id == \IPS\Member::loggedIn()->member_id) {
                    $handler->completeLink( \IPS\Member::loggedIn(), NULL );
                    $_SESSION['discord_reauthorized'] = TRUE;
                    \IPS\Output::i()->redirect(\IPS\Http\Url::internal('app=brilliantdiscord&module=xinvites&controller=invite&do=accept&icode=' . $this->invite->code, 'front', 'invite_accept')->csrf());
                } else {
                    \IPS\Output::i()->error(\IPS\Member::loggedIn()->language()->addToStack('profilesync_email_exists', FALSE, ['sprintf' => [$handler->_title]]), '1SBR100/5');
                }
            }
            throw $e;
        }
    }
	// Create new methods with the same name as the 'do' parameter which should execute it
};