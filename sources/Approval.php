<?php

namespace IPS\brilliantdiscord;

/* To prevent PHP errors (extending class does not exist) revealing path */
if (!defined('\IPS\SUITE_UNIQUE_KEY')) {
    header((isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0') . ' 403 Forbidden');
    exit;
}

class _Approval
{
    const TYPE_APPROVAL_REQUESTED = 1;
    const TYPE_APPROVAL_GIVEN = 2;

    const NO_ACCESS = 0;
    const ACCESS_REQUESTED = -1;
    const ACCESS_ONETIME = 1;
    const ACCESS_LIFETIME = 2;

    const ACTION_REQUEST = 0;
    const ACTION_ACCEPT = 1;
    const ACTION_APPROVE = 2;
    const ACTION_DENY = 3;
    const ACTION_DENY_MANUAL = 4;
    const ACTION_GIVE_ACCESS_LIFETIME = 7;

    public static $databaseTable = 'brilliantdiscord_approval_actions';

    /**
     * Returns approval logs for a member
     *
     * @param \IPS\Member|null $member
     * @param bool $decodeAdditionalData Decode 'additional_data' column?
     * @param string Order (by timestamp). Defaults to DESC
     * @return array
     */
    public static function logs($member = NULL, $decodeAdditionalData = TRUE, $order = 'DESC')
    {
        $data = iterator_to_array(\IPS\Db::i()->select('*', static::$databaseTable, ['`target_member`=?', ($member ?: \IPS\Member::loggedIn())->member_id], "`timestamp` $order"));
        if ($decodeAdditionalData) {
            return array_map(function ($v) {
                if ($v['additional_data'] != NULL) {
                    $v['additional_data'] = json_decode($v['additional_data'], TRUE);
                }
                return $v;
            }, $data);
        }
        return $data;
    }

    /**
     * Returns information about member's access to the Discord server.
     *
     * @param \IPS\Member|null $member
     * @return int
     */
    public static function access($member = NULL)
    {
        if (!Behavior::i()->enable_approval) return static::ACCESS_LIFETIME;
        $it = \IPS\Db::i()->select('type', static::$databaseTable, ['`target_member`=?', ($member ?: \IPS\Member::loggedIn())->member_id], '`timestamp` DESC', [0, 1]);
        try {
            $type = $it->first();
            if ($type == 0) return static::ACCESS_REQUESTED;
            if ($type == static::ACTION_APPROVE || $type == static::ACTION_GIVE_ACCESS_LIFETIME) return static::ACCESS_LIFETIME;
        } catch (\UnderflowException $e) {}
        return static::NO_ACCESS;
    }

    public static function log($action, $targetMember, $member, $additionalData)
    {
        \IPS\Db::i()->insert(static::$databaseTable, [
            'type' => $action,
            'target_member' => $targetMember->member_id,
            'member' => $member->member_id,
            'additional_data' => is_null($additionalData) ? NULL : json_encode($additionalData),
            'timestamp' => time()
        ]);
    }

    public static function waitingMembers()
    {
        $data = iterator_to_array(
            \IPS\Db::i()->select(
            // SELECT
                ['`a1`.`target_member`', '`a1`.`timestamp`'],
                // FROM
                ['brilliantdiscord_approval_actions', 'a1'],
                // WHERE
                '`a2`.`id` IS NULL AND `a1`.`type`=0'
            )->join(
            // LEFT JOIN
                ['brilliantdiscord_approval_actions', 'a2'],
                // ON
                '`a1`.`target_member` = `a2`.`target_member` AND `a1`.id < `a2`.id'
            )
        );
        return array_filter($data, function($row) {
            $member = \IPS\Member::load($row['target_member']);
            if (!$member->member_id) return FALSE;
            $lh = \IPS\Login\Handler::findMethod(LoginHandler::class)->link($member);
            return (bool) $lh;
        });
    }

    protected function dummy()
    {
    }
}