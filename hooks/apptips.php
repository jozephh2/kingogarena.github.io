//<?php

/* To prevent PHP errors (extending class does not exist) revealing path */
if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	exit;
}

class brilliantdiscord_hook_apptips extends _HOOK_CLASS_
{

/* !Hook Data - DO NOT REMOVE */
public static function hookData() {
 return array_merge_recursive( array (
  'appmenu' => 
  array (
    0 => 
    array (
      'selector' => '#acpAppList > li > ul.ipsList_reset.ipsScrollbar.ipsScrollbar_light > li > ul.ipsList_reset > li > a',
      'type' => 'add_inside_end',
      'content' => '{{if $tab == \'brilliantdiscord\' && $text = \IPS\brilliantdiscord\Application::helpTooltip($key)}}&nbsp;<span class=\'ipsNotificationCount\' data-ipstooltip title="{$text}">?</span>{{endif}}',
    ),
  ),
), parent::hookData() );
}
/* End Hook Data */


}
