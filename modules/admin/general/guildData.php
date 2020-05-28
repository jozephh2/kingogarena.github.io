<?php


namespace IPS\brilliantdiscord\modules\admin\general;

/* To prevent PHP errors (extending class does not exist) revealing path */
if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}
use \IPS\brilliantdiscord\modules\admin\general\configuration as ConfigurationController;
use IPS\brilliantdiscord\RateLimit\RateLimitedException;
use IPS\brilliantdiscord\Util\UnhandledDiscordException;

/**
 * guildData
 */
class _guildData extends \IPS\Dispatcher\Controller
{
	/**
	 * Execute
	 *
	 * @return	void
	 */
	public function execute()
	{
		\IPS\Dispatcher::i()->checkAcpPermission( 'brds_configuration_manage' );
		parent::execute();
	}

	//
	/**
	 * ...
	 *
	 * @return	void
	 */
	protected function manage()
	{
		if (!\IPS\Request::i()->token) {
		    \IPS\Output::i()->json(NULL, 400);
        } else {
		    // Retrieve guilds to provide easy guild select
            try {
                $self = $this;
                \IPS\brilliantdiscord\RateLimit::limitHandle('users/@me/guilds', NULL, function($check) use ($self) {
                    $request = new \IPS\brilliantdiscord\Request('users/@me/guilds');
                    $request->bot(\IPS\Request::i()->token);
                    $request->applyDefaultHeaders();
                    $response = $request->submit();

                    $check($response);

                    if ($response->httpResponseCode != 200) {
                        (new UnhandledDiscordException($request, $response))->safeHandle(FALSE);
                        \IPS\Output::i()->json(["code" => $response->httpResponseCode, "text" => $response->content], 500);
                    } else {
                        $result = ['guilds' => []];
                        $expected = ConfigurationController::$permissions;
                        foreach ($response->decodeJson() as $k => $v) {
                            $guild = ['name' => $v['name'], 'id' => $v['id']];
                            $permissionsMissing = ConfigurationController::_missingPermissions($expected, $v['permissions']);
                            if (!$permissionsMissing) {
                                $guild['enabled'] = TRUE;
                                $guild['messages'] = [
                                    [
                                        'success' => TRUE,
                                        'content' => \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_guild_perms_ok', FALSE),
                                    ]
                                ];
                            } else {
                                $guild['enabled'] = FALSE;
                                $guild['messages'] = [];
                                foreach ($permissionsMissing as $v) {
                                    $guild['messages'][] = [
                                        'success' => FALSE,
                                        'content' => \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_guild_missing_perm', FALSE, ['sprintf' => $v])
                                    ];
                                }
                            }
                            $result['guilds'][] = $guild;
                        }
                        $self->_sendOutput($result, 200);
                    }
                });
            } catch (RateLimitedException $e) {
                \IPS\Output::i()->json(["message" => $e->ipsMessage()], 429);
                return;
            }
        }
	}

    /**
     * Sends output to user
     *
     * @param $data JSON data to send
     * @param $httpStatusCode HTTP status code
     */
	protected function _sendOutput($data, $httpStatusCode) {
        \IPS\Member::loggedIn()->language()->parseOutputForDisplay( $data );
        $json = json_encode( $data );
        \IPS\Output::i()->sendOutput( $json, $httpStatusCode, 'application/json', \IPS\Output::i()->httpHeaders );
    }
	
	// Create new methods with the same name as the 'do' parameter which should execute it
}