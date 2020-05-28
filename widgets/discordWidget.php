<?php
/**
 * @brief		discordWidget Widget
 * @author		<a href='https://www.invisioncommunity.com'>Invision Power Services, Inc.</a>
 * @copyright	(c) Invision Power Services, Inc.
 * @license		https://www.invisioncommunity.com/legal/standards/
 * @package		Invision Community
 * @subpackage	brilliantdiscord
 * @since		29 Jan 2019
 */

namespace IPS\brilliantdiscord\widgets;

/* To prevent PHP errors (extending class does not exist) revealing path */
if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

/**
 * discordWidget Widget
 */
class _discordWidget extends \IPS\Widget
{
	/**
	 * @brief	Widget Key
	 */
	public $key = 'discordWidget';
	
	/**
	 * @brief	App
	 */
	public $app = 'brilliantdiscord';
		
	/**
	 * @brief	Plugin
	 */
	public $plugin = '';
	
	/**
	 * Initialise this widget
	 *
	 * @return void
	 */ 
	public function init()
	{
		// Use this to perform any set up and to assign a template that is not in the following format:
		// $this->template( array( \IPS\Theme::i()->getTemplate( 'widgets', $this->app, 'front' ), $this->key ) );
		// If you are creating a plugin, uncomment this line:
		// $this->template( array( \IPS\Theme::i()->getTemplate( 'plugins', 'core', 'global' ), $this->key ) );
		// And then create your template at located at plugins/<your plugin>/dev/html/discordWidget.phtml

		parent::init();
	}
	
	/**
	 * Specify widget configuration
	 *
	 * @param	null|\IPS\Helpers\Form	$form	Form object
	 * @return	null|\IPS\Helpers\Form
	 */
	public function configuration( &$form=null )
	{
 		if ( $form === null )
		{
	 		$form = new \IPS\Helpers\Form;
 		}

 		$prefix = 'brilliantdiscord_widget_';
 		if ( !\IPS\Settings::i()->brilliantdiscord_configured_guild ) {
 		    $form->addHtml(\IPS\Theme::i()->getTemplate('configuration', 'brilliantdiscord', 'admin')->info(\IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_widget_error_conf')));
        } else {
            $form->add( new \IPS\Helpers\Form\Select( 'brilliantdiscord_widget_type', $this->confDefault('type', 'banner2'), TRUE, ['options' => [
                'banner1' => $prefix.'type_banner1',
                'banner2' => $prefix.'type_banner2',
                'banner3' => $prefix.'type_banner3',
                'banner4' => $prefix.'type_banner4',
            ]] ) );
            $form->add( new \IPS\Helpers\Form\Node( 'brilliantdiscord_widget_invite', $this->confDefault('invite', 0), FALSE, ['class' => 'IPS\brilliantdiscord\Invite', 'zeroVal' => 'brilliantdiscord_widget_no_invite']  ));
        }

 		return $form;
 	} 

 	protected function confDefault($key, $default)
    {
        if (!isset($this->configuration[$key])) {
            return $default;
        } else {
            return $this->configuration[$key];
        }
    }

 	 /**
 	 * Ran before saving widget configuration
 	 *
 	 * @param	array	$values	Values from form
 	 * @return	array
 	 */
 	public function preConfig( $values )
 	{
 	    $len = mb_strlen('brilliantdiscord_widget_');
 	    foreach ($values as $k => $v) {
 	        unset($values[$k]);
 	        $values[mb_substr($k, $len)] = $v;
        }
 	    if ($values['invite'] != 0) {
 	        $values['invite'] = $values['invite']->_id;
        }
 		return $values;
 	}

	/**
	 * Render a widget
	 *
	 * @return	string
	 */
	public function render()
	{
	    if (!\IPS\Settings::i()->brilliantdiscord_configured_guild) return '';
	    $gid = \IPS\Settings::i()->brilliantdiscord_guild;
	    $invite = $this->confDefault('invite', NULL);
	    try {
	        if ($invite != NULL) $invite = \IPS\brilliantdiscord\Invite::load($invite);
        } catch ( \OutOfRangeException $e ) {
	        $invite = NULL;
        }
        $type = $this->confDefault('type', 'banner2');
	    //throw new \UnderflowException((string)$invite->url());
		return $this->output("https://discordapp.com/api/guilds/$gid/widget.png?style=$type", $invite == NULL ? NULL : (string) $invite->url());
		// Use $this->output( $foo, $bar ); to return a string generated by the template set in init() or manually added via $widget->template( $callback );
		// Note you MUST route output through $this->output() rather than calling \IPS\Theme::i()->getTemplate() because of the way widgets are cached
	}
}