<?php


namespace IPS\brilliantdiscord\modules\admin\general;

/* To prevent PHP errors (extending class does not exist) revealing path */

use IPS\brilliantdiscord\Approval;
use IPS\brilliantdiscord\RateLimit;
use IPS\brilliantdiscord\RateLimit\RateLimitedException;
use IPS\brilliantdiscord\Request;
use IPS\brilliantdiscord\Util\UnhandledDiscordException;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

/**
 * configuration
 */
class _configuration extends \IPS\Dispatcher\Controller
{
    public static $permissions = [
        'CREATE_INSTANT_INVITE' => 0x00000001,
        'KICK_MEMBERS' => 0x00000002,
        'MANAGE_CHANNELS' => 0x00000010,
        'MANAGE_GUILD' => 0x00000020,
        'VIEW_AUDIT_LOG' => 0x00000080,
        'MANAGE_NICKNAMES' => 0x08000000,
        'MANAGE_ROLES' => 0x10000000,
        'MANAGE_WEBHOOKS' => 0x20000000,
        'MANAGE_EMOJIS' => 0x40000000
    ];

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

	/**
	 * ...
	 *
	 * @return	void
	 */
	protected function manage()
	{
        if (\IPS\Member::loggedIn()->hasAcpRestriction( 'brilliantdiscord', 'general', 'brds_configuration_clear_data' )) {
            \IPS\Output::i()->sidebar['actions']['clear'] = [
                'primary'	=> false,
                'icon'	=> 'trash-o',
                'title'	=> 'brilliantdiscord_configuration_clear',
                'link'	=> \IPS\Http\Url::internal( "app=brilliantdiscord&module=general&controller=configuration&do=clearData" )->csrf(),
            ];
        }
	    if (!\IPS\Settings::i()->brilliantdiscord_configured) {
	        // Begin configuration
            \IPS\Output::i()->cssFiles = array_merge(
                \IPS\Output::i()->cssFiles,
                \IPS\Theme::i()->css( 'general/begin.css', 'brilliantdiscord', 'admin' )
            );
            \IPS\Output::i()->output .= \IPS\Theme::i()->getTemplate( 'configuration', 'brilliantdiscord' )->begin();
        } else {
	        // Sidebar buttons
            \IPS\Output::i()->sidebar['actions']['reconfigure'] = [
                'primary'	=> false,
                'icon'	=> 'cogs',
                'title'	=> 'brilliantdiscord_configuration_reconfigure',
                'link'	=> \IPS\Http\Url::internal( "app=brilliantdiscord&module=general&controller=configuration&do=advancedSetup&_new=1" ),
            ];

            // Details editing form
            $form = new \IPS\Helpers\Form;
            $p = 'brilliantdiscord_wza_'; // Prefix

            // Tab 1. General settings
            $form->addTab($p.'general_tab');

            // Had we configured guild settings?
            $conf_g = \IPS\Settings::i()->brilliantdiscord_configured_guild;

            // We want to display a information about detected problems BEFORE everything, and after verifying values:
            // 1. We put blank information
            // 2. Then we edit it
            $form->addHtml('');

            // Client ID (application) can't be changed without changing everything.
            $form->add(new \IPS\Helpers\Form\Text($p . 'client_id', \IPS\Settings::i()->brilliantdiscord_cid, TRUE, ['disabled' => TRUE]));

            // But we allow editing changeable values:
            $form->add(new \IPS\Helpers\Form\Text($p . 'client_secret', \IPS\Settings::i()->brilliantdiscord_secret, TRUE));
            $form->add(new \IPS\Helpers\Form\Text($p . 'token', \IPS\Settings::i()->brilliantdiscord_token, TRUE));

            // Validate & save changed values
            if ($values = $form->values()) {
                // Delete prefixes
                foreach ($values as $k => $v) {
                    if (mb_substr($k, 0, 21) == $p) {
                        $values[mb_substr($k, 21)] = trim($v); // ...and trim values
                        unset($values[$k]);
                    }
                }

                // Verify token
                try {
                    RateLimit::limitHandle('oauth2/applications/@me', NULL, function ($check) use ($values, $form, $p) {
                        // Basic request settings
                        $request = new Request('oauth2/applications/@me');
                        $request->bot($values['token']);
                        $request->applyDefaultHeaders();

                        $response = $request->submit();
                        // Parse rate limits
                        $check($response);

                        // Anything's wrong?
                        if ($response->httpResponseCode != 200) {
                            switch ($response->httpResponseCode) {
                                case 401: // Unauthorized - token is invalid
                                    $form->elements[$p.'general_tab'][$p.'token']->error = \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_error_invalid_token');
                                    break;
                                default: // TODO handling more errors?
                                    $form->error = \IPS\Member::loggedIn()->language()->addToStack('generic_error'); // Something went wrong
                            }
                        } else {
                            // Check if this is token of the same app
                            try {
                                $json = $response->decodeJson();
                                if ($json['id'] == $values['client_id']) {
                                    // Confirmed, we can save data.
                                    $d = ['token' => 'token', 'client_secret' => 'secret'];
                                    foreach ($d as $k => $v) {
                                        $v = 'brilliantdiscord_' . $v;
                                        \IPS\Db::i()->update('core_sys_conf_settings', ['conf_value' => $values[$k]], ['conf_key=?', $v]);
                                        \IPS\Settings::i()->$v = $values[$k];
                                    }
                                    unset(\IPS\Data\Store::i()->settings);
                                } else {
                                    // Inconsistent data
                                    $form->elements[$p.'general_tab'][$p.'token']->error = \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_error_inconsistent_token');
                                }
                            } catch (\RuntimeException $e) {
                                // Something went wrong :(
                                $form->error = \IPS\Member::loggedIn()->language()->addToStack('generic_error');
                            }
                        }
                    });
                } catch ( RateLimitedException $e ) {
                    $form->error = $e->ipsMessage();
                    \IPS\Output::i()->output = $form;
                }
            }

            // Information about problems
            $problems = $this->_findProblems($conf_g ? \IPS\Settings::i()->brilliantdiscord_guild : NULL);
            $form->elements[$p.'general_tab'][0] = \IPS\Theme::i()->getTemplate('configuration', 'brilliantdiscord')->appInfo($problems);
            \IPS\Output::i()->output = $form;
        }
		\IPS\Output::i()->title  = \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_configuration');
	}

	protected function advancedSetup()
    {
        // Configuration check
        $conf = \IPS\Settings::i()->brilliantdiscord_configured;
        $conf_g = \IPS\Settings::i()->brilliantdiscord_configured_guild;

        $gotoguild = $conf && isset(\IPS\Request::i()->gotoguild);
        \IPS\Output::i()->cssFiles = array_merge(
            \IPS\Output::i()->cssFiles,
            \IPS\Theme::i()->css( 'general/misc.css', 'brilliantdiscord', 'admin' )
        );
        \IPS\Output::i()->jsFiles = array_merge(
            \IPS\Output::i()->jsFiles,
            \IPS\Output::i()->js('admin_config.js', 'brilliantdiscord' )
        );
        $wizard = new \IPS\Helpers\Wizard(
            [
                'brilliantdiscord_wza_step1' => function ($data) use ($conf, $gotoguild) {
                    if ($gotoguild) {
                        return [
                            'client_id' => \IPS\Settings::i()->brilliantdiscord_cid,
                            'client_secret' => \IPS\Settings::i()->brilliantdiscord_secret,
                            'token' => \IPS\Settings::i()->brilliantdiscord_token
                        ];
                    }
                    $p = 'brilliantdiscord_wza_'; // Prefix
                    $form = new \IPS\Helpers\Form('form1', 'brilliantdiscord_configure_next');

                    // Information about redirect URIs
                    $form->addHtml(\IPS\Theme::i()->getTemplate('configuration', 'brilliantdiscord')->info(
                        \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_wza_app_info')
                    ));
                    $form->addHtml(\IPS\Theme::i()->getTemplate('configuration', 'brilliantdiscord')->info(
                        \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_wza_redi_uri_info')
                    ));

                    // Fields
                    $form->add(new \IPS\Helpers\Form\Text($p . 'client_secret', $conf ? \IPS\Settings::i()->brilliantdiscord_secret : NULL, TRUE));
                    $form->add(new \IPS\Helpers\Form\Text($p . 'token', $conf ? \IPS\Settings::i()->brilliantdiscord_token : NULL, TRUE));

                    if ($values = $form->values()) {
                        // Delete prefixes
                        foreach ($values as $k => $v) {
                            if (mb_substr($k, 0, 21) == $p) {
                                $values[mb_substr($k, 21)] = trim($v);
                                unset($values[$k]);
                            }
                        }

                        // Validate token
                        $request = new Request('oauth2/applications/@me');
                        $request->applyDefaultHeaders();
                        $request->bot($values['token']);
                        $response = $request->submit();

                        // Something is wrong?
                        if ($response->httpResponseCode != 200) {
                            switch ($response->httpResponseCode) {
                                case 401: // Unauthorized - token is invalid
                                    $form->elements[''][$p.'token']->error = \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_error_invalid_token');
                                    return $form;
                                default: // TODO handling more errors?
                                    $exception = new UnhandledDiscordException($request, $response);
                                    $exception->safeHandle(FALSE);
                                    $form->error = \IPS\Member::loggedIn()->language()->addToStack('generic_error'); // Probably connection error, etc.
                                    return $form;
                            }
                        }
                        // Save Client ID
                        $values['client_id'] = $response->decodeJson()['id'];
                        \IPS\Settings::i()->changeValues([
                            'brilliantdiscord_cid' => $values['client_id']
                        ]);
                        return $values;
                    }

                    return $form;
                },
                'brilliantdiscord_wza_step2' => function ($data) use ($conf_g) {
                    $form = new \IPS\Helpers\Form('form2', 'brilliantdiscord_configure_next');
                    $p = 'brilliantdiscord_wza_'; // Prefix

                    // User should know that this is always configurable later
                    $form->addHtml(\IPS\Theme::i()->getTemplate('configuration', 'brilliantdiscord')->info(
                        \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_configurable_later')
                    ));

                    // Enable guild integration (deep lvl 1)?
                    $form->add( new \IPS\Helpers\Form\YesNo($p.'enable_deep1', TRUE, FALSE, ['togglesOn' => ['approval', 'autosync', 'guild']]));

                    $addURL = \IPS\Http\Url::external('https://discordapp.com/api/oauth2/authorize')->setQueryString([
                        'scope' => 'bot',
                        'client_id' => $data['client_id'],
                        'permissions' => array_sum(static::$permissions)
                    ]);
                    $exchangeURL = \IPS\Http\Url::internal('app=brilliantdiscord&module=general&controller=guildData')->setQueryString('token', $data['token']);

                    // Guild helper
                    $form->add(new \IPS\Helpers\Form\Custom($p.'guild', $conf_g ? \IPS\Settings::i()->brilliantdiscord_guild : -1, NULL, [
                        'getHtml'	=> function( $field ) use ( $addURL, $exchangeURL ) {
                            return \IPS\Theme::i()->getTemplate( 'configuration', 'brilliantdiscord' )->guildHelper( $field,
                                $exchangeURL, $addURL, $field->value
                            );
                        },
                        'validate'  => function( $field ) use ( $data ) {
                            if ($field->value == '__EMPTY') {
                                if ($field->required) {
                                    throw new \DomainException('form_required');
                                }
                                return;
                            }
                            try {
                                RateLimit::limitHandle('users/@me/guilds', NULL, function($check) use ($field, $data) {
                                    // Basic request settings
                                    $request = new Request("users/@me/guilds", $this->_guildFindQuery($field->value));
                                    $request->applyDefaultHeaders();
                                    $request->bot($data['token']);
                                    $response = $request->submit();

                                    // Check for rate limits
                                    $check($response);

                                    // Parse response
                                    if ($response->httpResponseCode != 200) {
                                        switch ($response->httpResponseCode) {
                                            // Something bad happened
                                            default:
                                                throw new \DomainException('generic_error');
                                        }
                                    } elseif (!$response->decodeJson()) {
                                        throw new \DomainException('brilliantdiscord_error_no_guild_access');
                                    } elseif ($missing = static::_missingPermissions(static::$permissions, $response->decodeJson()[0]['permissions'])) {
                                        throw new \DomainException(\IPS\Member::loggedIn()->addToStack('brilliantdiscord_error_permissions', FALSE,
                                            ['sprintf' => implode(", ", $missing)]
                                        ));
                                    }
                                });
                            } catch ( RateLimitedException $e ) {
                                throw new \DomainException($e->ipsMessage());
                            }
                        }
                    ], NULL, NULL, NULL, 'guild'));

                    // Parse values
                    if ($values = $form->values()) {
                        $return = $data;
                        foreach (['guild', 'autosync', 'approval'] as $v) {
                            $return[$v] = $values[$p . $v];
                        }
                        if ($values[$p.'enable_deep1']) {
                            if ($return['guild'] == '__EMPTY') {
                                $form->elements[''][$p.'guild']->error = \IPS\Member::loggedIn()->language()->addToStack('form_required');
                                return $form;
                            }
                        } else {
                            $return['guild'] = -1;
                        }
                        return $return;
                    }
                    return $form;
                },
                'brilliantdiscord_wza_step3' => function ($data) use ($conf_g) {
                    if ($data['guild'] == -1) return $data;

                    $form = new \IPS\Helpers\Form;
                    try {
                        $roles = ['no_role' => ''];
                        foreach (\IPS\brilliantdiscord\Util\Guild::roles($data['guild'], $data['token']) as $k => $v) $roles[$k] = $v;
                        $form->add( new \IPS\Helpers\Form\Select( 'brilliantdiscord_behavior_form_basic_role', $conf_g ? \IPS\brilliantdiscord\Behavior::i()->basic_role : 'no_role', TRUE, ['parse' => 'normal', 'options' => $roles], function($val) {
                            if ($val == 'no_role') {
                                throw new \DomainException('form_required');
                            }
                        } ) );
                    } catch (RateLimitedException $e) {
                        $form->add( new \IPS\Helpers\Form\Select( 'brilliantdiscord_behavior_form_basic_role', $conf_g ? \IPS\brilliantdiscord\Behavior::i()->basic_role : 'no_role', TRUE, ['parse' => 'normal', 'options' => ['no_role' => '']], function($val) {
                            if ($val == 'no_role') {
                                throw new \DomainException('form_required');
                            }
                        } ) );
                        $form->elements['']['brilliantdiscord_behavior_form_basic_role']->error = $e->ipsMessage();
                    }

                    if ($values = $form->values()) {
                        \IPS\brilliantdiscord\Behavior::i()->basic_role = $values['brilliantdiscord_behavior_form_basic_role'];
                        return $data;
                    }
                    return $form;
                },
                'brilliantdiscord_wza_step4' => function ($data) use ($conf, $conf_g) {
                    $form = new \IPS\Helpers\Form('form4');

                    // Display an user-friendly information
                    $form->addHtml(\IPS\Theme::i()->getTemplate('configuration', 'brilliantdiscord')->allDone());

                    if ($form->values() !== FALSE) {
                        // Additional settings, just for easy check if app is configured or not
                        $data['configured'] = TRUE;
                        $data['configured_guild'] = $data['guild'] != -1;

                        // Save settings
                        $d = [];
                        foreach (['configured', 'configured_guild', 'token', 'guild'] as $v) {
                            $d['brilliantdiscord_' . $v] = $data[$v];
                        }
                        $d['brilliantdiscord_secret'] = $data['client_secret'];
                        \IPS\Settings::i()->changeValues($d);

                        // Enable login handler, as we had just configured it
                        \IPS\Db::i()->update('core_login_methods', ['login_enabled' => TRUE], ['login_classname=?', 'IPS\brilliantdiscord\LoginHandler']);
                        unset(\IPS\Data\Store::i()->loginMethods);

                        // If reconfigured and guild has changed - delete roles from group data
                        if ($conf_g && $data['guild'] != \IPS\Settings::i()->brilliantdiscord_guild) {
                            \IPS\Db::i()->update('brilliantdiscord_groupdata', ['discord_roles' => NULL]);
                        }

                        // Finished - redirect to the configuration overview
                        \IPS\Output::i()->redirect(\IPS\Http\Url::internal('app=brilliantdiscord&module=general&controller=configuration'), 'saved');
                    }
                    return $form;
                }
            ],
            \IPS\Http\Url::internal('app=brilliantdiscord&module=general&controller=configuration&do=advancedSetup' . ($gotoguild ? '&gotoguild=1' : ''))
        );
        \IPS\Output::i()->title = \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_wza_title');
        \IPS\Output::i()->output = $wizard;
    }

    public static function _missingPermissions($expected, $actual, $acceptAdministrator = TRUE)
    {
        if ($acceptAdministrator && ($actual & 8) == 8) {
            return [];
        }
        $missing = [];
        foreach ($expected as $k => $v) {
            if (($v & $actual) == 0) {
                $missing[] = $k;
            }
        }
        return $missing;
    }

    protected function _findProblems($guild = NULL)
    {
        $request = new Request("users/@me/guilds", $guild ? $this->_guildFindQuery($guild) : []);
        $request->bot();
        $request->applyDefaultHeaders();
        $response = $request->submit();
        $dataInfo = ['error' => NULL];
        try {
            $json = $response->decodeJson();
        } catch (\RuntimeException $e) {
            return ['error' => 'generic'];
        }
        if ($response->httpResponseCode != 200) {
            switch ($response->httpResponseCode) {
                case 401:
                    $dataInfo['error'] = 'badtoken';
                    break;
                default:
                    $dataInfo['error'] = 'generic';
            }
        } elseif ($guild && (!$json || $json[0]['id'] != $guild)) {
            $dataInfo['error'] = 'glost';
        } elseif ($guild && $perms = static::_missingPermissions(static::$permissions, $json[0]['permissions'])) {
            $dataInfo['error'] = 'perms';
            $dataInfo['missingPerms'] = $perms;
        }
        return $dataInfo;
    }

    protected function _guildFindQuery($id) {
	    $query = ['limit' => 1];
	    switch (mb_substr($id, -1)) {
            case '0':
                $query['after'] = \intval($id) - 1;
                break;
            default:
                $query['after'] = mb_substr($id, 0, -1) . (\intval(mb_substr($id, -1)) - 1);
        }
        return $query;
    }

    protected function clearData() {
	    \IPS\Session::i()->csrfCheck();
	    \IPS\Dispatcher::i()->checkAcpPermission('brds_configuration_clear_data');
        $p = 'brilliantdiscord_cldf_';
	    $form = new \IPS\Helpers\Form('form', $p.'proceed');
	    $form->addHtml(\IPS\Theme::i()->getTemplate('configuration', 'brilliantdiscord')->info(\IPS\Member::loggedIn()->language()->addToStack($p.'warning'), FALSE, 'warning'));
	    $options = [];
	    $configuration = [];
        foreach (['behavior', 'groups'] as $v) $configuration[$v] = $p.$v;
        foreach (['ratelimits', 'member_links', 'logs'] as $v) $options[$v] = $p.$v;
        $form->add( new \IPS\Helpers\Form\YesNo($p.'full_conf', FALSE, FALSE, ['togglesOff' => ['configuration_checks']]) );
	    $form->add( new \IPS\Helpers\Form\CheckboxSet($p.'configuration', [], FALSE, ['options' => $configuration], NULL, NULL, NULL, 'configuration_checks') );
	    $form->add( new \IPS\Helpers\Form\CheckboxSet($p.'another', [], FALSE, ['options' => $options]) );

	    if ($values = $form->values()) {
	        $options = \is_array($values[$p.'another']) ? $values[$p.'another'] : [$values[$p.'another']];
	        foreach ($options as $v) {
	            switch ($v) {
                    case "ratelimits":
                        \IPS\Db::i()->delete('brilliantdiscord_ratelimits');
                        break;
                    case "logs":
                        \IPS\Db::i()->delete('brilliantdiscord_logs');
                        break;
                    case "member_links":
                        \IPS\Db::i()->delete('core_login_links', ['`token_login_method`=?', \IPS\Login\Handler::findMethod(\IPS\brilliantdiscord\LoginHandler::class)->id]);
                        break;
                }
            }
	        if ($values[$p.'full_conf']) {
                \IPS\Settings::i()->changeValues([
                    'brilliantdiscord_configured' => FALSE,
                    'brilliantdiscord_configured_guild' => FALSE,
                ]);
                \IPS\brilliantdiscord\Behavior::i()->resetToDefault();
                \IPS\Db::i()->delete('brilliantdiscord_groupdata');
                \IPS\Db::i()->update('core_login_methods', ['login_enabled' => FALSE], ['login_classname=?', 'IPS\brilliantdiscord\LoginHandler']);
                unset(\IPS\Data\Store::i()->loginMethods);

            } else {
                $conf = \is_array($values[$p.'configuration']) ? $values[$p.'configuration'] : [$values[$p.'configuration']];
                foreach ($conf as $v) {
                    switch ($v) {
                        case "behavior":
                            \IPS\brilliantdiscord\Behavior::i()->resetToDefault();
                            break;
                        case "groups":
                            \IPS\Db::i()->delete('brilliantdiscord_groupdata');
                            break;
                    }
                }
            }
	        \IPS\Output::i()->redirect(\IPS\Http\Url::internal('app=brilliantdiscord&module=general&controller=configuration'), 'brilliantdiscord_success');
        }
	    \IPS\Output::i()->title = \IPS\Member::loggedIn()->language()->addToStack($p.'title');
	    \IPS\Output::i()->output = $form;
    }

    protected function richdiscord() {
	    if (!\IPS\Application::appIsEnabled('richdiscord') && \IPS\Application::load('richdiscord')->isConfigured()) {
	        \IPS\Output::i()->error('brilliantdiscord_configuration_richdiscord_err', '2SBR101/1', 404);
        }
        \IPS\Output::i()->cssFiles = array_merge(
            \IPS\Output::i()->cssFiles,
            \IPS\Theme::i()->css( 'general/richdiscord.css', 'brilliantdiscord', 'admin' ),
            \IPS\Theme::i()->css( 'general/misc.css', 'brilliantdiscord', 'admin' )
        );
	    \IPS\Output::i()->title = \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_migrate_title');

	    $stupid_notifications = file_exists( \IPS\ROOT_PATH . '/applications/richdiscord/hooks/forumsTopic.php');
	    $stupid_login_handlers = class_exists('IPS\richdiscord\Login\Handler\OAuth2\Discord');
	    $wizard = new \IPS\Helpers\Wizard([
	        'brilliantdiscord_migrate_step1' => function() {
	            $form = new \IPS\Helpers\Form('form1', 'brilliantdiscord_configure_next');
                if ($form->values() === FALSE) {
                    $form->addHtml(\IPS\Theme::i()->getTemplate('configuration', 'brilliantdiscord')->info(
                        \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_wza_redi_uri_info')
                    ));
                    $request = new Request('oauth2/applications/@me');
                    $request->applyDefaultHeaders();
                    $request->bot(\IPS\Settings::i()->richdiscord_token);
                    $response = $request->submit();
                    $json = $response->decodeJson();
                    $data = [];
                    switch ($response->httpResponseCode) {
                        case 200:
                            $data['id'] = $json['id'];
                            $data['name'] = $json['name'];
                            $data['owner_tag'] = $json['owner']['username'] . '#' . $json['owner']['discriminator'];
                            $data['avatar'] = $json['icon'] == NULL ? NULL : (string) \IPS\brilliantdiscord\CdnUtil::appIcon($json['id'], $json['icon']);
                            break;
                        case 401:
                            \IPS\Output::i()->error('brilliantdiscord_configuration_richdiscord_outdated', '4SBR101/2');
                            break;
                        default:
                            (new UnhandledDiscordException($request, $response))->safeHandle();
                    }
                    $form->add( new \IPS\Helpers\Form\Custom('brilliantdiscord_migrate_app_info', TRUE, FALSE, [
                        'getHtml' => function ($field) use ($data) {
                            return \IPS\Theme::i()->getTemplate('migrate', 'brilliantdiscord')->richdiscordInfo($data);
                        },
                        'formatValue' => function () {
                            return TRUE;
                        }
                    ] ) );
                } else {
                    \IPS\Settings::i()->changeValues([
                        'brilliantdiscord_cid' => \IPS\Settings::i()->richdiscord_client_id
                    ]);
                    return [
                        'token' => \IPS\Settings::i()->richdiscord_token,
                        'cid' => \IPS\Settings::i()->richdiscord_client_id,
                        'secret' => \IPS\Settings::i()->richdiscord_secret,
                    ];
                }
                return $form;
            },
            'brilliantdiscord_migrate_step2' => function ($data) {
	            $form = new \IPS\Helpers\Form('formstep2', 'brilliantdiscord_configure_next');
                if (isset(\IPS\Request::i()->formstep2_submitted) && isset(\IPS\Request::i()->only_login_st)) {
                    $settings = [
                        'brilliantdiscord_configured' => TRUE,
                        'brilliantdiscord_configured_guild' => FALSE,
                        'brilliantdiscord_cid' => $data['cid'],
                        'brilliantdiscord_token' => $data['token'],
                        'brilliantdiscord_secret' => $data['secret'],
                    ];
                    \IPS\Settings::i()->changeValues($settings);
                    \IPS\Output::i()->redirect(\IPS\Http\Url::internal('app=brilliantdiscord&controller=configuration&module=general'), 'saved');
                }

                $guild = NULL;
                $gid = \IPS\Settings::i()->richdiscord_guild;
                $result = NULL;
                try {
                    $result = RateLimit::limitHandle('users/@me/guilds', NULL, function ($check) use ($gid, $data, &$form) {
                        // Basic request settings
                        $request = new Request("users/@me/guilds", $this->_guildFindQuery($gid));
                        $request->applyDefaultHeaders();
                        $request->bot($data['token']);
                        $response = $request->submit();

                        // Check for rate limits
                        $check($response);

                        // Parse response
                        $json = $response->httpResponseCode == 200 ? $response->decodeJson() : NULL;
                        if ($response->httpResponseCode != 200) {
                            $e = (new UnhandledDiscordException($request, $response));
                            $e->safeHandle(FALSE);
                            throw $e;
                        } elseif (!$json || $json[0]['id'] != $gid) {
                            $form->actionButtons = [];
                            $form->actionButtons[] = \IPS\Theme::i()->getTemplate( 'forms', 'core', 'global' )->button( 'brilliantdiscord_migrate_only_login', 'submit', null, 'ipsButton ipsButton_link', ['tabindex' => '2', 'accesskey' => 's']);
                            throw new \DomainException;
                        } elseif ($missing = static::_missingPermissions(static::$permissions, $json[0]['permissions'])) {
                            return ['gname' => "{$json[0]['name']} ({$json[0]['id']})", 'missing' => TRUE, 'perms' => $missing];
                        }
                        return ['gname' => "{$json[0]['name']} ({$json[0]['id']})", 'missing' => FALSE];
                    });
                } catch (RateLimitedException $e) {
                    $form->addHtml(\IPS\Theme::i()->getTemplate('configuration', 'brilliantdiscord')->info($e->ipsMessage(), FALSE, 'error'));
                    $form->actionButtons = [\IPS\Theme::i()->getTemplate( 'forms', 'core', 'global' )->button( 'brilliantdiscord_migrate_refresh', 'link', null, 'ipsButton ipsButton_link', ['data-action' => 'wizardLink', 'tabindex' => '2', 'accesskey' => 's'])];
                    return $form;
                } catch (UnhandledDiscordException $e) {
                    $form->error = \IPS\Member::loggedIn()->language()->addToStack('generic_error');
                    return $form;
                } catch (\DomainException $e) {
                    $form->addHtml(\IPS\Theme::i()->getTemplate('configuration', 'brilliantdiscord')->info(\IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_richdiscord_notinguild'), TRUE, 'error'));
                    $form->hiddenValues['only_login_st'] = TRUE;
                    return $form;
                }
                $missingPermissions = $result['missing'] ? $result['perms'] : [];

                /*$form->add( new \IPS\Helpers\Form\YesNo('brilliantdiscord_migrate_guild', TRUE, FALSE, [
                    'togglesOn' => ['permissionslist']
                ]));*/

                $form->add( new \IPS\Helpers\Form\Custom('brilliantdiscord_migrate_permissions', NULL, TRUE, [
                    'getHtml' => function ($field) use ($result, $missingPermissions) {
                        return \IPS\Theme::i()->getTemplate('migrate', 'brilliantdiscord')->migratePermissions($field, $result['gname'], $missingPermissions);
                    },
                    'formatValue' => function($field) {
                        return 'ok';
                    },
                    'validate' => function($field) use ($missingPermissions) {
                        if ($missingPermissions != NULL) {
                            throw new \DomainException('brilliantdiscord_error_migrate_permissions');
                        }
                    }
                ], NULL, NULL, NULL, 'permissionslist' ) );

                if ($values = $form->values()) {
                    $data['guild'] = \IPS\Settings::i()->richdiscord_guild;
                    return $data;
                    /*if ($values['brilliantdiscord_migrate_guild']) {
                        $data['guild'] = \IPS\Settings::i()->richdiscord_guild;
                        return $data;
                    }
                    return ['skipGuild' => TRUE, 'data' => $data];*/
                }
                return $form;
            },
            'brilliantdiscord_migrate_step3' => function ($data) use ($stupid_notifications) {
	            //if (isset($data['skipGuild'])) return $data['data'];
                $form = new \IPS\Helpers\Form('form3', 'brilliantdiscord_configure_next');

                //$form->add( new \IPS\Helpers\Form\YesNo('brilliantdiscord_migrate_groupdata', TRUE, FALSE) );
                if (\IPS\Settings::i()->richdiscord_enable_queue) {
                    $form->add( new \IPS\Helpers\Form\YesNo('brilliantdiscord_migrate_aprqueue', TRUE, FALSE, ['togglesOn' => ['aprqueue_waiting_action']]) );
                    $form->add( new \IPS\Helpers\Form\Radio('brilliantdiscord_migrate_aprqueue_action', 1, FALSE, [
                        'options' => [
                            1 => 'brilliantdiscord_migrate_aprqueue_kickandmove',
                            2 => 'brilliantdiscord_migrate_aprqueue_kickwaiting',
                        ]
                    ], NULL, NULL, NULL, 'aprqueue_waiting_action'));
                } else {
                    $form->hiddenValues['brilliantdiscord_migrate_aprqueue'] = FALSE;
                    $form->hiddenValues['brilliantdiscord_migrate_aprqueue_action'] = 0;
                }

                try {
                    $roles = ['no_role' => ''];
                    foreach (\IPS\brilliantdiscord\Util\Guild::roles($data['guild'], $data['token'], $data['cid']) as $k => $v) $roles[$k] = $v;
                    $form->add( new \IPS\Helpers\Form\Select( 'brilliantdiscord_behavior_form_basic_role', 'no_role', TRUE, ['parse' => 'normal', 'options' => $roles], function($val) {
                        if ($val == 'no_role') {
                            throw new \DomainException('form_required');
                        }
                    } ) );
                } catch (RateLimitedException $e) {
                    $form->add( new \IPS\Helpers\Form\Select( 'brilliantdiscord_behavior_form_basic_role', 'no_role', TRUE, ['parse' => 'normal', 'options' => ['no_role' => '']], function($val) {
                        if ($val == 'no_role') {
                            throw new \DomainException('form_required');
                        }
                    } ) );
                    $form->elements['']['brilliantdiscord_behavior_form_basic_role']->error = $e->ipsMessage();
                }

                if ($values = $form->values()) {
                    $data['__beh_enable_approval'] = $values['brilliantdiscord_migrate_aprqueue'];
                    $data['__beh_basic_role'] = $values['brilliantdiscord_behavior_form_basic_role'];
                    $data['aprqueue_action'] = $values['brilliantdiscord_migrate_aprqueue_action'];
                    //$data['move_grouproles'] = $data['brilliantdiscord_migrate_groupdata'];
                    return $data;
                }

                return $form;
            },
            /*'brilliantdiscord_migrate_step4' => function ($data) use ($stupid_login_handlers) {
	            $form = new \IPS\Helpers\Form('form4', 'brilliantdiscord_configure_next');
                if ($stupid_login_handlers) {
                    $form->addHtml(\IPS\Theme::i()->getTemplate('configuration', 'brilliantdiscord')->info(\IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_migrate_loginupdate')));
                }
                $plg = 'brilliantdiscord_migrate_ltype_';
                $opts = [
                    1 => $plg.'glinks',
                ];
                if ($stupid_login_handlers) {
                    $opts[2] = $plg.'llinks';
                    $opts[3] = $plg.'forceselect';
                }
                $form->add(new \IPS\Helpers\Form\Select('brilliantdiscord_migrate_links', $stupid_login_handlers ? 3 : 1, NULL, [
                    'options' => $opts,
                    'unlimited' => -1,
                    'unlimitedLang' => 'brilliantdiscord_migrate_nolinks',
                ], NULL, NULL, NULL));

	            if ($values = $form->values()) {
	                $data['links'] = $values['brilliantdiscord_migrate_links'];
	                return $data;
                }
                return $form;
            },*/
            'brilliantdiscord_migrate_summary' => function ($data) {
	            $form = new \IPS\Helpers\Form('form', 'brilliantdiscord_migrate_proceed');
                $steps = [
                    'authdata', 'data', 'grouproles', 'links'
                ];
                if (\IPS\Application::appIsEnabled('forums') && \IPS\Settings::i()->richdiscord_sendnotification) $steps[] = 'notifications';
                if ($data['aprqueue_action'] != 0) $steps[] = 'aprqueue';
	            $form->addHtml(\IPS\Theme::i()->getTemplate('migrate', 'brilliantdiscord', 'admin')->summary($steps));
	            if ($form->values() !== FALSE) {
	                $app = \IPS\Application::load('richdiscord');
	                $app->_enabled = FALSE;
	                $app->save();
	                $_SESSION['bdirdimigrate'] = json_encode($data);
	                \IPS\Output::i()->redirect(\IPS\Http\Url::internal('app=brilliantdiscord&module=general&controller=configuration&do=rdimigration'));
                }
	            return $form;
            }
        ], \IPS\Http\Url::internal('app=brilliantdiscord&module=general&controller=configuration&do=richdiscord'));
	    \IPS\Output::i()->output = $wizard;
    }

    protected function _ulg($k) {
	    return \IPS\Member::loggedIn()->language()->get($k);
    }

    public function rdimigration()
    {
        if (isset($_SESSION['bdirdimigrate'])) {
            $data = $_SESSION['bdirdimigrate'];
            unset( $_SESSION['bdirdimigrate'] );
            $_SESSION['bdirdimigrate'] = $data;
        }
        $multiRedirect = new \IPS\Helpers\MultipleRedirect(
            \IPS\Http\Url::internal('app=brilliantdiscord&module=general&controller=configuration&do=rdimigration'),
            function( $data ) use ( $self )
            {
                if (!\is_array($data)) {
                    $rdata = json_decode($_SESSION['bdirdimigrate'], TRUE);
                    $steps = [
                        'authdata', 'links'
                    ];
                    $membersoverall = NULL;
                    if (\IPS\Application::appIsEnabled('forums') && \IPS\Settings::i()->richdiscord_sendnotification) $steps[] = 'notifications';
                    $steps[] = 'grouproles';
                    // Temporarily save managed roles as they won't change
                    $managed = [];
                    foreach (\IPS\Member\Group::groups(TRUE, FALSE) as $v) {
                        $vgr = $v->g_richdiscord_roles;
                        if (\is_array($vgr)) {
                            foreach ($vgr as $role) $managed[$role] = TRUE;
                        } else {
                            $managed[$vgr] = TRUE;
                        }
                    }
                    \IPS\Data\Store::i()->discord_richmanagedroles = $managed;
                    if ($rdata['aprqueue_action'] != 0) {
                        // Get user \count to give a percentage progress of kicking members waiting for approval

                        // Temporarily set GID to RDI's GID
                        \IPS\Settings::i()->brilliantdiscord_token = $rdata['token'];
                        \IPS\Settings::i()->brilliantdiscord_guild = $rdata['guild'];
                        $membersoverall = \IPS\brilliantdiscord\Util\Guild::guildData(300, TRUE)['overall'];
                        $steps[] = 'aprqueue';
                    }
                    $prmax = \count($steps) + ($membersoverall ?: 0)  - 1;
                    $steps[] = 'finish';
                    $data = $rdata;
                    $data['steps'] = $steps;
                    $data['prmax'] = $prmax;
                    $data['progress'] = 0;
                    $data['mo'] = $membersoverall;
                    return [$data, \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_migration_process_start'), 0];
                }
                $ptext = NULL;
                $progress = $data['progress'];
                $prmax = $data['prmax'];

                $step = NULL;
                foreach ($data['steps'] as $s) {
                    $step = $s;
                    break;
                }
                switch ($step) {
                    case 'authdata':
                        \IPS\Settings::i()->changeValues([
                            'brilliantdiscord_guild' => $data['guild'],
                            'brilliantdiscord_cid' => $data['cid'],
                            'brilliantdiscord_token' => $data['token'],
                            'brilliantdiscord_secret' => $data['secret']
                        ]);
                        \IPS\brilliantdiscord\Behavior::i()->setMultiple([
                            'enable_approval' => $data['__beh_enable_approval'],
                            'basic_role' => $data['__beh_basic_role'],
                        ]);
                        \IPS\Db::i()->update('core_login_methods', ['login_enabled' => TRUE], ['login_classname=?', 'IPS\brilliantdiscord\LoginHandler']);
                        unset(\IPS\Data\Store::i()->loginMethods);
                        array_shift($data['steps']);
                        $ptext = 'brilliantdiscord_migration_authdata';
                        $progress++;
                        break;
                    case 'links':
                        $prefix = \IPS\Db::i()->prefix;

                        $methodId = \IPS\Login\Handler::findMethod(\IPS\brilliantdiscord\LoginHandler::class)->_id;

                        // Delete possibly existing links
                        \IPS\Db::i()->delete('core_login_links', ['token_login_method=?', $methodId]);

                        \IPS\Db::i()->query(
                            <<<SQL
INSERT INTO {$prefix}core_login_links (token_login_method, token_linked, token_member, token_identifier)
SELECT {$methodId}, 1, `member_id`, `richdiscord_id`
FROM {$prefix}core_members WHERE `richdiscord_id` IS NOT NULL
SQL
                        );
                        array_shift($data['steps']);
                        $ptext = 'brilliantdiscord_migration_links';
                        $progress++;
                        break;
                    case 'grouproles':
                        $prefix = \IPS\Db::i()->prefix;

                        \IPS\Db::i()->query(
                            <<<SQL
INSERT INTO {$prefix}brilliantdiscord_groupdata (discord_roles, bypass_approval, group_id)
SELECT `g_richdiscord_roles`, 0, `g_id`
FROM {$prefix}core_groups
SQL
                        );

                        array_shift($data['steps']);
                        $ptext = 'brilliantdiscord_migration_grouproles';
                        $progress++;
                        break;
                        break;

                    case 'notifications':
                        // Check webhook
                        $regex = '/^(https:\/\/)?(canary\.)?discordapp\.com\/api(\/v6)?\/webhooks\/(\d+\/.+)/';;

                        $webhookurl = \IPS\Settings::i()->richdiscord_webhookurl;
                        if (!preg_match($regex, $webhookurl, $matches)) {
                            $webhook = '__UNMIGRATED__';
                        } else {
                            $webhook = $matches[4];

                            $request = new Request("webhooks/$webhook");
                            $request->applyDefaultHeaders();
                            $response = $request->submit();
                            if ($response->httpResponseCode != 200 || $response->decodeJson()['guild_id'] != \IPS\Settings::i()->brilliantdiscord_guild) {
                                $webhook = '__UNMIGRATED__';
                            }
                        }

                        foreach ([
                            'forums' => [\IPS\forums\Topic::class, 'Topics', 'topic'],
                            'forums_post' => [\IPS\forums\Topic\Post::class, 'Posts', 'post']
                        ] as $k => $v) {
                            $stg = \IPS\Settings::i()->{"richdiscord_".$k};
                            if ($stg === NULL) continue;

                            $n = new \IPS\brilliantdiscord\Notification;
                            $n->position = \IPS\Db::i()->select( 'MAX(position)', 'brilliantdiscord_notifications' )->first() + 1;
                            $n->item_class = $v[0];
                            $n->webhook = $webhook;
                            $n->enabled = $webhook != '__UNMIGRATED__';
                            $n->name = "{$v[1]} (migrated from Rich Discord Integration)";
                            $n->notification_settings = [
                                'type' => 'message',
                                'message' => sprintf(
                                    \IPS\Lang::load(\IPS\Lang::defaultLanguage())
                                        ->get( 'richdiscord_' . $v[2] . '_notification' ),
                                    '${author}', '${title}', '${url}'
                                )
                            ];
                            $n->conditions = $stg == 0 ? NULL : [
                                "category" => $stg
                            ];
                            $n->save();
                        }

                        array_shift($data['steps']);
                        $ptext = 'brilliantdiscord_migration_notifications';
                        $progress++;
                        break;
                    case 'aprqueue':
                        if (!isset($data['apprafter'])) $data['apprafter'] = 0;
                        $managedroles = \IPS\Data\Store::i()->discord_richmanagedroles;
                        $ptext = 'brilliantdiscord_migration_aprqueue';
                        $gid = \IPS\Settings::i()->richdiscord_guild;
                        $rl_global = RateLimit::globalEndpoint();
                        $rl_list = RateLimit::endpoint('guilds/{guild.id}/members', $gid);
                        $rl_modify = RateLimit::endpoint('guilds/{guild.id}/members/{member.id}');

                        $wait = max(array_map(function($rl) {
                            return $rl->isAvailable() ? -1 : $rl->reset_time;
                        }, [$rl_global, $rl_list, $rl_modify]));

                        if ($wait != -1) {
                            time_sleep_until($wait);
                            break;
                        }

                        $members = RateLimit::limitHandle('guilds/{guild.id}/members', $gid, function($check) use ($gid, $data) {
                            $request = new Request("guilds/$gid/members", ['limit' => 1000, 'after' => $data['apprafter']]);
                            $request->applyDefaultHeaders();
                            $request->bot(\IPS\Settings::i()->brilliantdiscord_token);
                            $response = $request->submit();
                            $check($response);
                            if ($response->httpResponseCode != 200) {
                                (new UnhandledDiscordException($request, $response))->safeHandle();
                            }
                            return $response->decodeJson();
                        });

                        $mcount = 0;
                        foreach ($members as $k => $v) {
                            $mcount++;
                            if (isset($v['bot'])) {
                                $progress++;
                                $data['apprafter'] = $v['user']['id'];
                                continue;
                            }

                            $isset = FALSE;
                            foreach ($v['roles'] as $role) {
                                if (isset($managedroles[$role])) {
                                    $isset = TRUE;
                                    break;
                                }
                            }
                            if (!$isset) {
                                try {
                                    $member_id = \IPS\Db::i()->select('token_member', 'core_login_links', ['token_identifier=?', $v['user']['id']])->first();
                                    $member = \IPS\Member::load($member_id);
                                    $progress++;
                                    $data['apprafter'] = $v['user']['id'];
                                    if ($member->member_id != $member_id) continue;
                                } catch (\UnderflowException $e) {
                                    $progress++;
                                    $data['apprafter'] = $v['user']['id'];
                                    continue;
                                }
                                if ($data['aprqueue_action'] == 1) $member->discordAction(Approval::ACTION_REQUEST, $member);
                                try {
                                    RateLimit::limitHandle('guilds/{guild.id}/members/{member.id}', $gid, function($check) use ($gid, $v) {
                                        $request = new Request("guilds/$gid/members/{$v['user']['id']}");
                                        $request->applyDefaultHeaders();
                                        $request->bot(\IPS\Settings::i()->brilliantdiscord_token);
                                        $response = $request->submit('DELETE');
                                        $check($response);

                                        if (!\in_array($response->httpResponseCode, [200, 204])) {
                                            // Log that error
                                            (new UnhandledDiscordException($request, $response))->safeHandle(FALSE);
                                        }
                                    });
                                    $progress++;
                                    $data['apprafter'] = $v['user']['id'];
                                    $rl_modify = RateLimit::endpoint('guilds/{guild.id}/members/{member.id}');
                                    if (!$rl_modify->isAvailable()) break;
                                } catch (RateLimitedException $e) {
                                    break;
                                }
                            }
                        }

                        if ($mcount == 0) {
                            array_shift($data['steps']);
                        }

                        break;
                    case 'finish':
                        \IPS\Settings::i()->changeValues([
                            'brilliantdiscord_configured' => TRUE,
                            'brilliantdiscord_configured_guild' => TRUE
                        ]);
                        return NULL;
                }

                $data['progress'] = $progress;
                $data['prmax'] = $prmax;
                return [$data, \IPS\Member::loggedIn()->language()->get($ptext)
                    , round((100 / $data['prmax']) * $data['progress'])];
            },
            function()
            {
                \IPS\Output::i()->redirect(\IPS\Http\Url::internal('app=brilliantdiscord&module=general&controller=configuration'), 'brilliantdiscord_success');
            }
        );

        \IPS\Output::i()->title = \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_migration');
        \IPS\Output::i()->output = $multiRedirect;
    }
    // Create new methods with the same name as the 'do' parameter which should execute it
}