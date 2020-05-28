<?php

namespace IPS\brilliantdiscord\Util;

/* To prevent PHP errors (extending class does not exist) revealing path */
if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

use IPS\brilliantdiscord\RateLimit;
use IPS\brilliantdiscord\Request;

class _Guild
{
    /**
     * Access guild data
     *
     * @param int $optionalInviteAge Maximum lifespan of optionally created invite
     * @param bool $noCache Whetther to use cached data or not
     * @return array
     */
    public static function guildData($optionalInviteAge = 3600, $noCache=FALSE)
    {
        //if (!\IPS\Settings::i()->brilliantdiscord_configured_guild) throw new \BadMethodCallException;
        // Cache data
        if ($noCache || !isset(\IPS\Data\Store::i()->discord_guild_data) || \IPS\Data\Store::i()->discord_guild_data['timestamp'] + 600 < time()) {
            $gid = \IPS\Settings::i()->brilliantdiscord_guild;
            RateLimit::limitHandle('guilds/{guild.id}/invites', $gid, function ($check) use ($optionalInviteAge, $gid) {
                $request = new Request("guilds/$gid/invites");
                $request->applyDefaultHeaders();
                $request->bot();
                $response = $request->submit();
                $check($response);

                switch ($response->httpResponseCode) {
                    case 200:
                        $json = $response->decodeJson();
                        if (!$json) { // No invites found, create a new one.
                            // Find a channel
                            RateLimit::limitHandle('guilds/{guild.id}/channels', $gid, function ($check) use (&$code, $optionalInviteAge, $gid) {
                                $request = new Request("guilds/$gid/channels");
                                $request->applyDefaultHeaders();
                                $request->bot();
                                $response = $request->submit();
                                $check($response);
                                if ($response->httpResponseCode != 200) {
                                    (new UnhandledDiscordException($request, $response))->safeHandle();
                                } else {
                                    $cid = NULL;
                                    foreach ($response->decodeJson() as $v) {
                                        // Make sure if it's not a category
                                        if ($v['type'] != 4) {
                                            $cid = $v['id'];
                                            break;
                                        }
                                    }
                                    if ($cid == NULL) {
                                        throw new \RuntimeException("Can't retrieve online members: no channels found on Discord server.");
                                    }
                                    $code = RateLimit::limitHandle('channels/{channel.id}/invites', $cid, function ($check) use ($optionalInviteAge, $cid) {
                                        $request = new Request("channels/$cid/invites");
                                        $request->applyDefaultHeaders();
                                        $request->bot();
                                        $response = $request->submit('POST', json_encode([
                                            'max_age' => $optionalInviteAge
                                        ]));
                                        $check($response);
                                        if ($response->httpResponseCode != 200) {
                                            (new UnhandledDiscordException($request, $response))->safeHandle();
                                        } else {
                                            return $response->decodeJson()['code'];
                                        }
                                    });
                                }
                            });
                        } else {
                            $code = $json[0]['code'];
                        }
                        $request = new Request("invite/$code?with_counts=true");
                        $request->applyDefaultHeaders();
                        $response = $request->submit();
                        if ($response->httpResponseCode != 200) {
                            (new UnhandledDiscordException($request, $response))->safeHandle();
                        } else {
                            $json = $response->decodeJson();
                            // Cache data
                            $avatar = \IPS\brilliantdiscord\CdnUtil::guildIcon($gid, $json['guild']['icon']);
                            if ($avatar != NULL) {
                                $avatar = (string) $avatar;
                            }
                            \IPS\Data\Store::i()->discord_guild_data = [
                                'timestamp' => time(),
                                'name' => $json['guild']['name'],
                                'letters' => static::lettersForIcon($json['guild']['name']),
                                'avatar' => $avatar,
                                'online' => $json['approximate_presence_count'],
                                'overall' => $json['approximate_member_count']
                            ];
                        }
                        break;
                    default:
                        (new UnhandledDiscordException($request, $response))->safeHandle(); // todo discord unhandled request errors
                }
            });
        }
        return \IPS\Data\Store::i()->discord_guild_data;
    }

    public static function lettersForIcon($name) {
        $takeNext = TRUE;
        $letters = [];
        foreach (str_split($name) as $char) {
            if ($char == ' ') {
                $takeNext = TRUE;
                continue;
            }
            if (!preg_match('/\d|[a-z]/i', $char)) {
                $letters[] = $char;
                $takeNext = TRUE;
                continue;
            }
            if ($takeNext) {
                $letters[] = $char;
                $takeNext = FALSE;
                continue;
            }
        }
        return implode('', $letters);
    }

    public static function roles($gid = NULL, $token = NULL, $identifier=NULL) {
        $gid = $gid ?: \IPS\Settings::i()->brilliantdiscord_guild;
        return RateLimit::limitHandle('guilds/{guild.id}/roles', $gid, function($check) use ($gid, $token) {
            $request = new Request("guilds/{$gid}/roles");
            $request->applyDefaultHeaders();
            $request->bot($token);
            $response = $request->submit();
            $check($response);
            if ($response->httpResponseCode != 200) {
                (new UnhandledDiscordException($request, $response))->safeHandle();
            } else {
                $roles = [];
                foreach ($response->decodeJson() as $role) {
                    if ($role['managed'] || $role['id'] == $gid) continue;
                    $roles[$role['id']] = $role['name'];
                }
                return $roles;
            }
        }, $identifier ?: \IPS\Settings::i()->brilliantdiscord_cid);
    }

    protected function dummy() {}
}