<?php
/**
 * @brief		Background Task
 * @author		<a href='https://www.invisioncommunity.com'>Invision Power Services, Inc.</a>
 * @copyright	(c) Invision Power Services, Inc.
 * @license		https://www.invisioncommunity.com/legal/standards/
 * @package		Invision Community
 * @subpackage	Brilliant Discord Integration
 * @since		04 Feb 2019
 */

namespace IPS\brilliantdiscord\extensions\core\Queue;

/* To prevent PHP errors (extending class does not exist) revealing path */
if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

/**
 * Background Task
 */
class _MassSynchronization
{
	/**
	 * Parse data before queuing
	 *
	 * @param	array	$data
	 * @return	array
	 */
	public function preQueueData( $data )
	{
	    // Reset cache
        unset( \IPS\Data\Store::i()->discord_guild_data );
        $data['handler_id'] = \IPS\Login\Handler::findMethod(\IPS\brilliantdiscord\LoginHandler::class)->_id;
		$data['count'] = \IPS\Db::i()->select('COUNT(*)', 'core_login_links', ["`token_login_method`=? AND `token_access_token` IS NOT NULL", $data['handler_id']])->first();
        $app_roles = [];
        foreach (\IPS\Member\Group::groups(TRUE, FALSE) as $v) {
            foreach ($v->discord_roles ?: [] as $role) {
                $app_roles[] = $role;
            }
        }
        $gid = \IPS\Settings::i()->brilliantdiscord_guild;
        $data['owner_id'] = \IPS\brilliantdiscord\RateLimit::limitHandle('guilds/{guild.id}', $gid, function ($check) use ($gid) {
            $request = new \IPS\brilliantdiscord\Request("guilds/$gid");
            $request->applyDefaultHeaders();
            $request->bot();
            $response = $request->submit();
            $check($response);
            if ($response->httpResponseCode == 200) {
                return $response->decodeJson()['owner_id'];
            } else {
                $e = new \IPS\brilliantdiscord\Util\UnhandledDiscordException($request, $response);
                $e->safeHandle(FALSE);
                throw $e;
            }
        });
        $data['app_roles'] = $app_roles;
		return $data;
	}

	/**
	 * Run Background Task
	 *
	 * @param	mixed						$data	Data as it was passed to \IPS\Task::queue()
	 * @param	int							$offset	Offset
	 * @return	int							New offset
	 * @throws	\IPS\Task\Queue\OutOfRangeException	Indicates offset doesn't exist and thus task is complete
	 */
	public function run( $data, $offset )
	{
        $maxUnavailable = -1;
        $globalLimit = \IPS\brilliantdiscord\RateLimit::globalEndpoint();
        $gid = \IPS\Settings::i()->brilliantdiscord_guild;
		$editRateLimit = \IPS\brilliantdiscord\RateLimit::endpoint('guilds/{guild.id}/members/{member.id}', $gid);
		foreach([$globalLimit, $editRateLimit] as $rateLimit) {
		    if (!$rateLimit->isAvailable()) {
		        $maxUnavailable = max($maxUnavailable, $rateLimit->reset_time);
            }
        }
		if ($maxUnavailable != -1) {
		    time_sleep_until($editRateLimit->reset_time);
		    return $offset;
        }
		$remainingRequests = $editRateLimit->remaining;
		// If we are here and it's equal to 0, it means that we don't know what are the rate limits of this endpoint, so... we request it to get info about it (todo better solution)
		if ($remainingRequests == 0) {
		    $rq = new \IPS\brilliantdiscord\Request("guilds/$gid/members/0");
		    $rq->applyDefaultHeaders();
		    $rq->bot();
		    $result = \IPS\brilliantdiscord\RateLimit::parseResponse($rq->submit(), 'guilds/{guild.id}/members/{member.id}', $gid);
		    return $offset;
        }
		$membersToRequest = min($remainingRequests-1, $data['count'] - $offset);
		// Select these links
        $links = iterator_to_array(\IPS\Db::i()->select(['token_identifier', 'token_member'], 'core_login_links', ["`token_login_method`=? AND `token_linked`=1", $data['handler_id']], NULL, [$offset, $membersToRequest]));
        $linksCount = \count($links);
        if ($linksCount == 0) throw new \IPS\Task\Queue\OutOfRangeException; // We can stop if there are no links left

		// Now we can do anything
        $counter = $remainingRequests;
        $linkCounter = 0;
        foreach ($links as $link) {
            if ($counter == 0) return $offset+$linksCount;
            if ($counter == 1) {
                return $offset+$linksCount-1;
                break;
            }
            $mid_discord = $link['token_identifier'];
            $member = \IPS\Member::load($link['token_member']);
            if ($mid_discord == $data['owner_id']) continue;
            if ($member->isBanned()) {
                $syncRequest = new \IPS\brilliantdiscord\Request("guilds/$gid/members/$mid_discord");
                $syncRequest->applyDefaultHeaders();
                $syncRequest->bot();
                $syncRequest->submit('delete');
                $counter--;
                $linkCounter++;
                continue;
            }

            $check = new \IPS\brilliantdiscord\Request("guilds/$gid/members/$mid_discord");
            $check->applyDefaultHeaders();
            $check->bot();
            $checkResult = $check->submit();
            $counter--;
            switch ($checkResult->httpResponseCode) {
                case 200:
                    break;
                case 404:
                    continue 2;
                case 429:
                    return $offset+$linkCounter;
                default:
                    (new \IPS\brilliantdiscord\Util\UnhandledDiscordException($check, $checkResult))->safeHandle(FALSE);
                    continue 2;
            }
            $discordMember = $checkResult->decodeJson();

            // Now we can sync :)
            $collector = [];
            foreach ($discordMember['roles'] as $role) $collector[$role] = TRUE;
            foreach ($data['app_roles'] as $role) $collector[$role] = FALSE;
            foreach ($member->discordRoles() as $role) $collector[$role] = TRUE;
            $rolesToSet = array_keys(array_filter($collector));

            $syncRequest = new \IPS\brilliantdiscord\Request("guilds/$gid/members/$mid_discord");
            $syncRequest->applyDefaultHeaders();
            $syncRequest->bot();
            $response = $syncRequest->submit('patch', json_encode($member->discordPatchBody($rolesToSet)));
            $counter--;
            if ($response->httpResponseCode == 429) return $offset+$linkCounter;
            if (!\in_array($response->httpResponseCode, [204, 403])) {
                // Log this error
                (new \IPS\brilliantdiscord\Util\UnhandledDiscordException($syncRequest, $response))->safeHandle(FALSE);
            }
            $linkCounter++;
        }
        if ($linksCount < $membersToRequest) throw new \IPS\Task\Queue\OutOfRangeException;
		return $offset+$linksCount;
	}
	
	/**
	 * Get Progress
	 *
	 * @param	mixed					$data	Data as it was passed to \IPS\Task::queue()
	 * @param	int						$offset	Offset
	 * @return	array( 'text' => 'Doing something...', 'complete' => 50 )	Text explaining task and percentage complete
	 * @throws	\OutOfRangeException	Indicates offset doesn't exist and thus task is complete
	 */
	public function getProgress( $data, $offset )
	{
		return array( 'text' => \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_mass_sync_text'), 'complete' => $offset == 0 ? 0 : round(min(100, 100 / ( $data['count'] / $offset ) )) );
	}

	/**
	 * Perform post-completion processing
	 *
	 * @param	array	$data
	 * @return	void
	 */
	public function postComplete( $data )
	{

	}
}