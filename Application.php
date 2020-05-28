<?php
/**
 * @brief		Brilliant Discord Integration Application Class
 * @author		<a href=''>Software Factory</a>
 * @copyright	(c) 2018 Software Factory
 * @package		Invision Community
 * @subpackage	Brilliant Discord Integration
 * @since		09 Dec 2018
 * @version		
 */
 
namespace IPS\brilliantdiscord;

/* To prevent PHP errors (extending class does not exist) revealing path */
if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
    header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
    exit;
}

/**
 * Brilliant Discord Integration Application Class
 */
class _Application extends \IPS\Application
{
	protected function get__icon()
    {
        return 'diamond';
    }

    public function get__badge()
    {
        return parent::get__badge() ?: [0 => "positive", 1 => "brilliantdiscord_legit_badge"];
    }

    public function set__enabled($enabled)
    {
        parent::set__enabled($enabled);
        // Change login handler's state, as it depends on the app
        \IPS\Db::i()->update('core_login_methods', ['login_enabled' => ((bool) $enabled) && \IPS\Settings::i()->brilliantdiscord_configured], ['login_classname=?', 'IPS\brilliantdiscord\LoginHandler']);
        unset(\IPS\Data\Store::i()->loginMethods);
    }

    /**
     * ACP Menu Numbers
     *
     * @param	array	$queryString	Query String
     * @return	int
     */
    public function acpMenuNumber( $queryString )
    {
        parse_str( $queryString, $queryString );
        if (\IPS\Settings::i()->brilliantdiscord_configured_guild && Behavior::i()->enable_approval && $queryString['controller'] == 'approvalqueue') {
            return \count(Approval::waitingMembers());
        } else {
            return 0;
        }
    }

    public static function acpConfCheck($guild = FALSE)
    {
        if (!\IPS\Settings::i()->brilliantdiscord_configured) \IPS\Output::i()->error('brilliantdiscord_error_inconfigured', '1SBR000/2', 400);
        if (!\IPS\Settings::i()->brilliantdiscord_configured_guild) \IPS\Output::i()->error('brilliantdiscord_error_inconfigured_guild', '1SBR000/3', 400);
    }

    public function installOther()
    {
        $position = \IPS\Db::i()->select( 'MAX(login_order)', 'core_login_methods' )->first();

        $handler = new LoginHandler;
        $handler->classname = LoginHandler::class;
        $handler->order = $position + 1;
        $handler->acp = TRUE;
        $handler->settings = [
            'discord_username' => "0",
            'show_in_ucp' => 'always',
            'update_name_changes' => 'disabled',
            'update_email_changes' => 'optional',
        ];
        $handler->enabled = FALSE;
        $handler->register = FALSE;
        $handler->save();

        \IPS\Lang::saveCustom( 'core', "login_method_{$handler->id}", 'Discord' );
        unset(\IPS\Data\Store::i()->loginMethods);
    }

    public static function helpTooltip($controller) {
        return;
    }
}