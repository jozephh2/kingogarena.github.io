//<?php

/* To prevent PHP errors (extending class does not exist) revealing path */

use IPS\brilliantdiscord\Invite;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	exit;
}

class brilliantdiscord_hook_member extends _HOOK_CLASS_
{
    protected static $_approvalInfoCache = [];
    public function discordLink() {
	try
	{
	        return \IPS\Login\Handler::findMethod(\IPS\brilliantdiscord\LoginHandler::class)->link($this);
	}
	catch ( \RuntimeException $e )
	{
		if ( method_exists( get_parent_class(), __FUNCTION__ ) )
		{
			return \call_user_func_array( 'parent::' . __FUNCTION__, \func_get_args() );
		}
		else
		{
			throw $e;
		}
	}
    }

    public function discordMember($link = NULL) {
	try
	{
	        if (!$link) {
	            $link = $this->discordLink();
	            if ($link == NULL) return NULL;
	        }
	        $mid = $link['token_identifier'];
	        $gid = \IPS\Settings::i()->brilliantdiscord_guild;
	        return \IPS\brilliantdiscord\RateLimit::limitHandle('guilds/{guild.id}/members/{member.id}', $gid, function($check) use ($mid, $gid) {
	            $request = new \IPS\brilliantdiscord\Request("guilds/$gid/members/$mid");
	            $request->applyDefaultHeaders();
	            $request->bot();
	            $response = $request->submit();
	            $check($response);
	            switch ($response->httpResponseCode) {
	                case 200:
	                    return $response->decodeJson();
	                case 404:
	                    return NULL;
	                default:
	                    (new \IPS\brilliantdiscord\Util\UnhandledDiscordException($request, $response))->safeHandle();
	                    return NULL;
	            }
	        });
	}
	catch ( \RuntimeException $e )
	{
		if ( method_exists( get_parent_class(), __FUNCTION__ ) )
		{
			return \call_user_func_array( 'parent::' . __FUNCTION__, \func_get_args() );
		}
		else
		{
			throw $e;
		}
	}
    }

    /**
     * Checks if member needs to be approved to join the server.
     *
     * @param $invite Invite Invite used (if applies)
     * @return bool
     */
    public function discordApprovalNeeded($invite = NULL) {
	try
	{
	        if (!\IPS\brilliantdiscord\Behavior::i()->enable_approval) return FALSE;
	        if ($invite != NULL && $invite->can('bypass_approval', $this)) return TRUE;
	        if (!isset(static::$_approvalInfoCache[$this->member_id])) {
	            $groups = $this->mgroups_others ? explode(",", $this->mgroup_others) : [];
	            $groups[] = $this->member_group_id;
	            static::$_approvalInfoCache[$this->member_id] = !((bool) \IPS\Db::i()->select("SUM(bypass_approval)", "brilliantdiscord_groupdata", \IPS\Db::i()->in('group_id', $groups))->first());
	        }
	        return static::$_approvalInfoCache[$this->member_id];
	}
	catch ( \RuntimeException $e )
	{
		if ( method_exists( get_parent_class(), __FUNCTION__ ) )
		{
			return \call_user_func_array( 'parent::' . __FUNCTION__, \func_get_args() );
		}
		else
		{
			throw $e;
		}
	}
    }

    /**
     * Single member synchronization function, should not be used for mass synchronization
     */
    public function discordSync($link = NULL) {
	try
	{
	        if (!$this->member_id) return;
	        if (!$link) {
	            $link = $this->discordLink();
	            if ($link == NULL) return;
	        }
	        $member = $this->discordMember($link);
	        if ($member == NULL) return;
	        if ($this->isBanned()) {
	            $this->discordKick();
	            return;
	        }
	        $collector = [];
	        foreach ($member['roles'] as $role) $collector[$role] = TRUE;
	        foreach (\IPS\Member\Group::groups(TRUE, FALSE) as $v) {
	            foreach ($v->discord_roles ?: [] as $role) {
	                $collector[$role] = FALSE;
	            }
	        }
	        foreach ($this->discordRoles(TRUE) as $role) {
	            $collector[$role] = TRUE;
	        }
	
	        $collector[\IPS\brilliantdiscord\Behavior::i()->basic_role] = TRUE;
	        $rolesToSet = array_keys(array_filter($collector, function ($val) {return $val;}));
	        $gid = \IPS\Settings::i()->brilliantdiscord_guild;
	        $mid = $link['token_identifier'];
	        $self = $this;
	        \IPS\brilliantdiscord\RateLimit::limitHandle('guilds/{guild.id}/members/{member.id}', $gid, function($check) use ($gid, $rolesToSet, $mid, $self) {
	            $request = new \IPS\brilliantdiscord\Request("guilds/$gid/members/$mid");
	            $request->applyDefaultHeaders();
	            $request->bot();
	            $response = $request->submit('patch', json_encode($self->discordPatchBody($rolesToSet)));
	            $check($response);
	            switch ($response->httpResponseCode) {
	                case 200:
	                    break;
	                case 204:
	                    break;
	                case 403: // no permission
	                    throw new \OutOfRangeException;
	                case 404:
	                    throw new \UnderflowException;
	                default:
	                    (new \IPS\brilliantdiscord\Util\UnhandledDiscordException($request, $response))->safeHandle(TRUE, '5SBR103/1');
	            }
	        });
	}
	catch ( \RuntimeException $e )
	{
		if ( method_exists( get_parent_class(), __FUNCTION__ ) )
		{
			return \call_user_func_array( 'parent::' . __FUNCTION__, \func_get_args() );
		}
		else
		{
			throw $e;
		}
	}
    }

    public function discordRoles($resetGroups = FALSE) {
	try
	{
	        if ($resetGroups) $this->_groups = NULL;
	        $roles = [\IPS\brilliantdiscord\Behavior::i()->basic_role => TRUE];
	        foreach ($this->groups as $gid) {
	            try {
	                foreach (\IPS\Member\Group::load($gid)->discord_roles ?: [] as $role) {
	                    $roles[$role] = TRUE;
	                }
	            } catch (\OutOfRangeException $e) {}
	        }
	        return array_keys(array_filter($roles));
	}
	catch ( \RuntimeException $e )
	{
		if ( method_exists( get_parent_class(), __FUNCTION__ ) )
		{
			return \call_user_func_array( 'parent::' . __FUNCTION__, \func_get_args() );
		}
		else
		{
			throw $e;
		}
	}
    }

    public function discordKick() {
	try
	{
	        $link = $this->discordLink();
	        if ($link == NULL) return FALSE;
	        $gid = \IPS\Settings::i()->brilliantdiscord_guild;
	        $mid = $link['token_identifier'];
	        \IPS\brilliantdiscord\RateLimit::limitHandle('guilds/{guild.id}/members/{member.id}', $gid, function($check) use ($gid, $mid) {
	            $request = new \IPS\brilliantdiscord\Request("guilds/$gid/members/$mid");
	            $request->applyDefaultHeaders();
	            $request->bot();
	            $response = $request->submit('DELETE');
	            $check($response);
	            switch ($response->httpResponseCode) {
	                case 200:
	                    return 200;
	                case 204:
	                    return 204;
                /**
                 * Disable inspection, as we want to run default behavior if it's not a ban.
                 * @noinspection PhpMissingBreakStatementInspection
                 */
	                case 403:
	                    if ($response->decodeJson()['code'] == 50013) {
	                        return 403;
	                    }
	                default:
	                    throw (new \IPS\brilliantdiscord\Util\UnhandledDiscordException($request, $response))->safeHandle(TRUE, '5SBR103/2');
	            }
	        });
	}
	catch ( \RuntimeException $e )
	{
		if ( method_exists( get_parent_class(), __FUNCTION__ ) )
		{
			return \call_user_func_array( 'parent::' . __FUNCTION__, \func_get_args() );
		}
		else
		{
			throw $e;
		}
	}
    }

    /**
     * Forces member to join the Discord server (if possible).
     * Returns array in format [$request, $response] or NULL.
     *
     * @return array|NULL
     * @throws \IPS\Login\Exception
     * @throws \IPS\brilliantdiscord\RateLimit\RateLimitedException
     */
    public function discordForceJoin() {
	try
	{
        /**
         * @var \IPS\brilliantdiscord\LoginHandler $handler
         */
	        $handler = \IPS\brilliantdiscord\LoginHandler::findMethod(\IPS\brilliantdiscord\LoginHandler::class);
	        $link = $this->discordLink();
	        if ($link == NULL) return NULL;
        // It will throw an \IPS\Login\Exception if token is invalid etc.
	        $handler->userProfileName($this);
        // Prepare required data
	        $gid = \IPS\Settings::i()->brilliantdiscord_guild;
	        $mid = $link['token_identifier'];
	        $token = $link['token_access_token'];
	        $self = $this;
	        return \IPS\brilliantdiscord\RateLimit::limitHandle('guilds/{guild.id}/members/{member.id}', $gid, function($check) use ($self, $gid, $mid, $token) {
	            $request = new \IPS\brilliantdiscord\Request("guilds/$gid/members/$mid");
	            $request->applyDefaultHeaders();
	            $request->bot();
	            $body = $self->discordPatchBody();
	            $body['access_token'] = $token;
	            $response = $request->submit('put', json_encode($body));
	            $check($response);
	            return [$request, $response];
	        });
	}
	catch ( \RuntimeException $e )
	{
		if ( method_exists( get_parent_class(), __FUNCTION__ ) )
		{
			return \call_user_func_array( 'parent::' . __FUNCTION__, \func_get_args() );
		}
		else
		{
			throw $e;
		}
	}
    }

    /**
     * Returns TRUE if member can join the Discord server.
     *
     * @return bool
     */
    public function canAccessDiscord() {
	try
	{
	        return $this->discordLink() != NULL && !$this->isBanned();
	}
	catch ( \RuntimeException $e )
	{
		if ( method_exists( get_parent_class(), __FUNCTION__ ) )
		{
			return \call_user_func_array( 'parent::' . __FUNCTION__, \func_get_args() );
		}
		else
		{
			throw $e;
		}
	}
    }

    public function discordAction($type, $member, $log=TRUE, $additionalData=NULL) {
	try
	{
	        switch ($type) {
	            case \IPS\brilliantdiscord\Approval::ACTION_ACCEPT:
	            case \IPS\brilliantdiscord\Approval::ACTION_APPROVE:
	                $this->discordForceJoin();
	        }
	        if ($log) \IPS\brilliantdiscord\Approval::log($type, $this, $member, $additionalData);
	}
	catch ( \RuntimeException $e )
	{
		if ( method_exists( get_parent_class(), __FUNCTION__ ) )
		{
			return \call_user_func_array( 'parent::' . __FUNCTION__, \func_get_args() );
		}
		else
		{
			throw $e;
		}
	}
    }

    /**
     * Prepares body for Discord member synchronization.
     *
     * @param array|null $roles Roles to set or NULL for default
     * @return array Body object
     */
    public function discordPatchBody($roles = NULL)
    {
	try
	{
	        $body = ['roles' => $roles ? $roles : $this->discordRoles()];
	        if (\IPS\brilliantdiscord\Behavior::i()->sync_nicknames) $body['nick'] = $this->real_name;
	        return $body;
	}
	catch ( \RuntimeException $e )
	{
		if ( method_exists( get_parent_class(), __FUNCTION__ ) )
		{
			return \call_user_func_array( 'parent::' . __FUNCTION__, \func_get_args() );
		}
		else
		{
			throw $e;
		}
	}
    }

    /**
     * @inheritDoc
     */
    public function set_temp_ban($value)
    {
	try
	{
	        parent::set_temp_ban($value);
	        if ($value != 0) {
	            $this->discordKick();
	        }
	}
	catch ( \RuntimeException $e )
	{
		if ( method_exists( get_parent_class(), __FUNCTION__ ) )
		{
			return \call_user_func_array( 'parent::' . __FUNCTION__, \func_get_args() );
		}
		else
		{
			throw $e;
		}
	}
    }
}
