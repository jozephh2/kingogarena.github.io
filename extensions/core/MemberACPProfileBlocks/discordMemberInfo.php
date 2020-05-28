<?php
/**
 * @brief		ACP Member Profile Block
 * @author		<a href='https://www.invisioncommunity.com'>Invision Power Services, Inc.</a>
 * @copyright	(c) Invision Power Services, Inc.
 * @license		https://www.invisioncommunity.com/legal/standards/
 * @package		Invision Community
 * @subpackage	Brilliant Discord Integration
 * @since		31 Jan 2019
 */

namespace IPS\brilliantdiscord\extensions\core\MemberACPProfileBlocks;

/* To prevent PHP errors (extending class does not exist) revealing path */

use IPS\brilliantdiscord\RateLimit\RateLimitedException;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

/**
 * @brief	ACP Member Profile Block
 */
class _discordMemberInfo extends \IPS\core\MemberACPProfile\Block
{
	/**
	 * Get output
	 *
	 * @return	string
	 */
	public function output()
	{
        /**
         * @var \IPS\brilliantdiscord\LoginHandler $method
         */
        $method = \IPS\Login\Handler::findMethod('IPS\brilliantdiscord\LoginHandler');
        $access = FALSE;
        if ($method->canProcess($this->member)) {
            try {
                $method->userProfileName($this->member);
                $access = TRUE;
            } catch (\IPS\Login\Exception $e) {
                $access = FALSE;
            }
        }
        try {
            $member = $this->member->discordMember();
            if ($access == FALSE && $member == NULL) {
                return NULL;
            }
            return \IPS\Theme::i()->getTemplate('management', 'brilliantdiscord', 'admin')->memberBlock($this->member, $access, $member, [
                'sync' => \IPS\Http\Url::internal('app=brilliantdiscord&module=manage&controller=memberManage&do=synchronize&member=' . $this->member->member_id),
                'force_join' => \IPS\Http\Url::internal('app=brilliantdiscord&module=manage&controller=memberManage&do=forceJoin&member=' . $this->member->member_id),
                'kick' => \IPS\Http\Url::internal('app=brilliantdiscord&module=manage&controller=memberManage&do=kick&member=' . $this->member->member_id),
                'approve' => \IPS\Http\Url::internal('app=brilliantdiscord&module=manage&controller=memberManage&do=approve&member=' . $this->member->member_id),
                'disapprove' => \IPS\Http\Url::internal('app=brilliantdiscord&module=manage&controller=memberManage&do=disapprove&member=' . $this->member->member_id),
                'logs' => \IPS\Http\Url::internal('app=brilliantdiscord&module=manage&controller=memberManage&do=logs&member=' . $this->member->member_id),
            ]);
        } catch (RateLimitedException $e) {
            return \IPS\Theme::i()->getTemplate('management', 'brilliantdiscord', 'admin')->memberBlockRatelimit($e);
        }
	}
}