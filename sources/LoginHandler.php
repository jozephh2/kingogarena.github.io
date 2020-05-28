<?php

namespace IPS\brilliantdiscord;

/* To prevent PHP errors (extending class does not exist) revealing path */

use IPS\brilliantdiscord\RateLimit\RateLimitedException;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

class _LoginHandler extends \IPS\Login\Handler\OAuth2
{
    protected $_cachedUserData = [];

    public static $allowMultiple = false;

    /**
     * Returns instance of the Discord login handler.
     *
     * @return LoginHandler|NULL
     */
    public static function i()
    {
        return \IPS\Login\Handler::findMethod('IPS\brilliantdiscord\LoginHandler');
    }

    public function __construct()
    {
        parent::__construct();
        $stgs = $this->settings;
        $stgs['client_id'] = \IPS\Settings::i()->brilliantdiscord_cid;
        $stgs['client_secret'] = \IPS\Settings::i()->brilliantdiscord_secret;
        $this->settings = $stgs;
    }

    public function setDefaultValues()
    {
        parent::setDefaultValues();
        $stgs = $this->settings;
        $stgs['client_id'] = \IPS\Settings::i()->brilliantdiscord_cid;
        $stgs['client_secret'] = \IPS\Settings::i()->brilliantdiscord_secret;
        $this->settings = $stgs;
    }

    public static function getTitle()
    {
        return 'brilliantdiscord_login_title';
    }

    public function get__locked()
    {
        return TRUE;
    }

    public function get__description()
    {
        return \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_method_description');
    }

    /**
     * Get the button color
     *
     * @return    string
     */
    public function buttonColor()
    {
        return '#7289DA';
    }

    /**
     * Get the button icon
     *
     * @return string
     */
    public function buttonIcon()
    {
        return 'user-o bdi-fa-fab-discord';
    }

    /**
     * Get button text
     *
     * @return    string
     */
    public function buttonText()
    {
        return \IPS\Member::loggedIn()->language()->addToStack("brilliantdiscord_login_discord");
    }

    /**
     * Get button CSS class
     *
     * @return	string
     */
    public function buttonClass()
    {
        return 'brilliantdiscord_discordButton';
    }

    /**
     * Grant Type
     *
     * @return    string
     */
    protected function grantType()
    {
        return 'authorization_code';
    }

    /**
     * Authorization Endpoint
     *
     * @param    \IPS\Login $login The login object
     * @return    \IPS\Http\Url
     */
    protected function authorizationEndpoint(\IPS\Login $login)
    {
        return \IPS\Http\Url::external('https://discordapp.com/api/oauth2/authorize');
    }

    /**
     * Token Endpoint
     *
     * @return    \IPS\Http\Url
     */
    protected function tokenEndpoint()
    {
        return \IPS\Http\Url::external('https://discordapp.com/api/oauth2/token');
    }

    /**
     * Get authenticated user's identifier (may not be a number)
     *
     * @param    string $accessToken Access Token
     * @return    string
     */
    protected function authenticatedUserId($accessToken)
    {
        return $this->_userData($accessToken)['id'];
    }

    /**
     * Get user data
     *
     * @param	string	$accessToken	Access Token
     * @return	array
     * @throws	\IPS\Login\Exception	The token is invalid and the user needs to reauthenticate
     * @throws	\RuntimeException		Unexpected error from service
     */
    protected function _userData( $accessToken )
    {
        if ( !isset( $this->_cachedUserData[ $accessToken ] ) ) {
            try {
                RateLimit::limitHandle('users/@me', NULL, function($check) use ($accessToken) {
                    $request = new Request('users/@me');
                    $request->bearer($accessToken);
                    $request->applyDefaultHeaders();
                    $response = $request->submit();

                    if ( !\in_array($response->httpResponseCode, Request::successCodes()) ) {
                        try {
                            $json = $response->decodeJson();
                            if ( isset($json['message']) ) {
                                throw new \IPS\Login\Exception( "{$response->httpResponseCode}: " . $json['message'] . " ({$json['code']})", \IPS\Login\Exception::INTERNAL_ERROR );
                            } else if ( isset($json['code']) ) {
                                throw new \IPS\Login\Exception( "{$response->httpResponseCode}: {$json['code']})", \IPS\Login\Exception::INTERNAL_ERROR );
                            } else {
                                throw new \RuntimeException;
                            }
                        } catch ( \RuntimeException $e ) {
                            throw new \IPS\Login\Exception( "{$response->httpResponseCode}: " . $response->content, \IPS\Login\Exception::INTERNAL_ERROR );
                        }
                    }

                    $this->_cachedUserData[ $accessToken ] = $response->decodeJson();
                });
            } catch ( RateLimitedException $e ) {
                throw new \IPS\Login\Exception( "brilliantdiscord_login_rate_limit", \IPS\Login\Exception::INTERNAL_ERROR );
            }
        }
        return $this->_cachedUserData[ $accessToken ];
    }

    /**
     * Send request authenticated with client credentials
     *
     * @param	\IPS\Http\Url	$url	The URL
     * @return	\IPS\Http\Response
     */
    protected function _authenticatedRequest( \IPS\Http\Url $url, $data )
    {
        try {
            return RateLimit::limitHandle('oauth2/token', NULL, function($check) use ($url, $data) {
                $request = $url->request();
                if ( $this->_authenticationType() === static::AUTHENTICATE_HEADER )
                {
                    $request = $request->login( $this->settings['client_id'], $this->settings['client_secret'] );
                }
                else
                {
                    $data['client_id'] = $this->settings['client_id'];
                    $data['client_secret'] = $this->settings['client_secret'];
                }
                $response = $request->post( $data );
                $check($response);
                return $response;
            });
        } catch (RateLimitedException $e) {
            throw new \IPS\Login\Exception( "brilliantdiscord_login_rate_limit", \IPS\Login\Exception::INTERNAL_ERROR );
        }
    }

    /**
     * @inheritdoc
     */
    protected function scopesToRequest($additional = NULL)
    {
        return ["identify", "email", "guilds.join"];
    }

    /**
     * Get authenticated user's username
     * May return NULL if server doesn't support this
     *
     * @param	string	$accessToken	Access Token
     * @return	string|NULL
     */
    protected function authenticatedUserName( $accessToken )
    {
        if ( isset( $this->settings['discord_username'] ) and $this->settings['discord_username'] )
        {
            $data = $this->_userData( $accessToken );
            return $data['username'];
        }
        return NULL;
    }

    /**
     * Get user's profile name
     * May return NULL if server doesn't support this
     *
     * @param	\IPS\Member	$member	Member
     * @param   bool        $includeDiscriminator Whether to include discriminator in name or not
     * @return	string|NULL
     * @throws	\IPS\Login\Exception	The token is invalid and the user needs to reauthenticate
     * @throws	\DomainException		General error where it is safe to show a message to the user
     * @throws	\RuntimeException		Unexpected error from service
     */
    public function userProfileName( \IPS\Member $member, $includeDiscriminator=TRUE )
    {
        if ( !( $link = $this->_link( $member ) ) )
        {
            throw new \IPS\Login\Exception( 'generic_error', \IPS\Login\Exception::INTERNAL_ERROR );
        }

        $userData = $this->_userData( $link['token_access_token'] );
        return $userData['username'] . ($includeDiscriminator ? '#' . $userData['discriminator'] : '');
    }

    /**
     * Get authenticated user's email address
     * May return NULL if server doesn't support this
     *
     * @param	string	$accessToken	Access Token
     * @return	string|NULL
     */
    protected function authenticatedEmail( $accessToken )
    {
        return $this->_userData( $accessToken )['email'];
    }

    /**
     * Syncing Options
     *
     * @param	\IPS\Member	$member			The member we're asking for (can be used to not show certain options iof the user didn't grant those scopes)
     * @param	bool		$defaultOnly	If TRUE, only returns which options should be enabled by default for a new account
     * @return	array
     */
    public function syncOptions( \IPS\Member $member, $defaultOnly = FALSE )
    {
        $return = array();

        if ( !isset( $this->settings['update_email_changes'] ) or $this->settings['update_email_changes'] === 'optional' )
        {
            $return[] = 'email';
        }

        if ( isset( $this->settings['update_name_changes'] ) and $this->settings['update_name_changes'] === 'optional' and isset( $this->settings['discord_username'] ) and $this->settings['discord_username'] )
        {
            $return[] = 'name';
        }

        $return[] = 'photo';
        return $return;
    }

    /**
     * Get user's profile photo
     * May return NULL if server doesn't support this
     *
     * @param	\IPS\Member	$member	Member
     * @return	\IPS\Http\Url|NULL
     * @throws	\IPS\Login\Exception	The token is invalid and the user needs to reauthenticate
     * @throws	\DomainException		General error where it is safe to show a message to the user
     * @throws	\RuntimeException		Unexpected error from service
     */
    public function userProfilePhoto( \IPS\Member $member )
    {
        if ( !( $link = $this->_link( $member ) ) )
        {
            throw new \IPS\Login\Exception( 'generic_error', \IPS\Login\Exception::INTERNAL_ERROR );
        }

        $data = $this->_userData($link['token_access_token']);
        $photo = CdnUtil::avatar($data['id'], $data['avatar'], 'png', TRUE) ?: CdnUtil::defaultAvatar($data['discriminator']);
        return $photo;
    }

    /**
     * @inheritdoc
     */
    public function acpForm()
    {
        return array_merge(
            parent::acpForm(),
            array(
                'client_id'		=> new \IPS\Helpers\Form\Text( 'oauth_client_id', isset( $this->settings['client_id'] ) ? $this->settings['client_id'] : NULL, TRUE, ['disabled' => TRUE] ),
                'client_secret'	=> new \IPS\Helpers\Form\Text( 'oauth_client_client_secret', isset( $this->settings['client_secret'] ) ? $this->settings['client_secret'] : NULL, NULL, ['disabled' => TRUE], NULL, NULL, NULL, 'client_secret' ),
                'discord_username'	=> new \IPS\Helpers\Form\Radio( 'brilliantdiscord_use_discord_username', isset( $this->settings['discord_username'] ) ? $this->settings['discord_username'] : 1, FALSE, array(
                    'options' => array(
                        1			=> 'brilliantdiscord_login_discord_username',
                        0			=> 'login_real_name_disabled',
                    ),
                    'toggles' => array(
                        1			=> array( 'login_update_name_changes_inc_optional' ),
                    )
                ), NULL, NULL, NULL, 'use_discord_username' ),
            ));
    }

    public function get_settings()
    {
        return array_merge(parent::get_settings(), [
            'client_id' => \IPS\Settings::i()->brilliantdiscord_cid,
            'client_secret' => \IPS\Settings::i()->brilliantdiscord_secret
        ]);
    }

    public function link( $member = NULL )
    {
        return $this->_link( $member ?: \IPS\Member::loggedIn() );
    }

    public function canDelete()
    {
        return FALSE;
    }

    public function disassociate(\IPS\Member $member = NULL)
    {
        $member = $member ?: \IPS\Member::loggedIn();
        if (\IPS\Settings::i()->brilliantdiscord_configured_guild) {
            try {
                $member->discordKick();
            } catch (RateLimitedException $e) {
                \IPS\Output::i()->error($e->ipsMessage(), '1SBR107/1', 429);
            }
        }
        parent::disassociate($member);
    }

    // Automatically synchronize members that have joined the Discord server before linking their Discord account
    public function authenticateButton(\IPS\Login $login)
    {
        try {
            return parent::authenticateButton($login);
        } catch (\IPS\Login\Exception $e) {
            if ($e->getCode() === \IPS\Login\Exception::MERGE_SOCIAL_ACCOUNT) {
                try {
                    $link = \IPS\Db::i()->select( '*', 'core_login_links', array( 'token_login_method=? AND token_member=?', $this->id, $e->member->member_id ), NULL, NULL, NULL, NULL, \IPS\Db::SELECT_FROM_WRITE_SERVER )->first();
                    $e->member->discordSync($link);
                } catch ( \OutOfRangeException $e2 ) {
                } catch ( \UnderflowException  $e2 ) {
                } catch ( RateLimitedException $e2 ) {}
            }
            throw $e;
        }
    }

    /**
     * Retrieves username of a discord account.
     *
     * @param \IPS\Member|null Member to retrieve the username or NULL
     * @return string|null Member's username
     */
    public function discordUsername($member = NULL, $withDiscriminator = FALSE) {
        $member = $member ?: \IPS\Member::loggedIn();
        try {
            return $this->userProfileName($member, $withDiscriminator);
        } catch ( \IPS\Login\Exception $e ) {
            return NULL;
        }
    }
}