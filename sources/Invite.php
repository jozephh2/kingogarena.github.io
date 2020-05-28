<?php

namespace IPS\brilliantdiscord;

/* To prevent PHP errors (extending class does not exist) revealing path */
if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

class _Invite extends \IPS\Node\Model implements \IPS\Node\Permissions
{
    protected static $multitons = [];

    public static $modalForms = TRUE;

    public static $nodeTitle = 'brilliantdiscord_invites';
    public static $databaseTable = 'brilliantdiscord_xinvites';
    public static $databaseColumnOrder = 'position';
    public static $databaseColumnId = 'id';

    public static $permApp = 'brilliantdiscord';
    public static $permType = 'invites';
    public static $permissionLangPrefix = 'brilliantdiscord_invite_';

    public static $permissionMap = [
        'view' => 'view',
        'bypass_approval' => 2
    ];

    /**
     * @inheritdoc
     */
    public function url()
    {
        return \IPS\Http\Url::internal('app=brilliantdiscord&module=xinvites&controller=invite&icode=' . $this->code, 'front', 'invite');
    }

    /**
     * @inheritdoc
     */
    public function form(&$form)
    {
        $p = 'brilliantdiscord_f_xinvites_';

        $id = $this->id;
        $form->add( new \IPS\Helpers\Form\Text( $p.'code', $id ? $this->code : NULL, TRUE, [
            'disabled' => (bool) $this->id,
            'regex' => '/^[A-Z0-9_]+$/i'
        ], function ($v) use ($id) {
            if (!$id) {
                try {
                    \IPS\Db::i()->select('code', static::$databaseTable, ['code=?', $v], NULL, [0,1])->first();
                    throw new \DomainException('brilliantdiscord_invite_not_unique');
                } catch ( \UnderflowException $e ) {}
            }
        } ) );

        $form->add( new \IPS\Helpers\Form\Date( $p.'expiration', $id ? $this->expiration : -1, FALSE, [
            'time' => TRUE,
            'unlimited' => -1,
            'unlimitedLang' => 'never',
            'min' => \IPS\DateTime::create()
        ] ) );
    }

    public function formatFormValues($values)
    {
        $p = 'brilliantdiscord_f_xinvites_';
        foreach ($values as $k => $v) {
            $len = mb_strlen($p);
            if (mb_substr($k, 0, $len) == $p) {
                $values[mb_substr($k, $len)] = $v;
                unset($values[$k]);
            }
        }
        if ($values['expiration'] != -1) {
            $values['expiration'] = $values['expiration']->getTimestamp();
        }
        return parent::formatFormValues($values);
    }
    public static function load($id, $idField = NULL, $extraWhereClause = NULL)
    {
        $result = parent::load($id, $idField, $extraWhereClause);
        if ($result->expiration != -1 && $result->expiration <= time()) {
            unset(static::$multitons[$result->code]);
            $result->delete();
            throw new \OutOfRangeException;
        }
        return $result;
    }

    public static function constructFromData($data, $updateMultitonStoreIfExists = TRUE)
    {
        if ($data['expiration'] != -1 && $data['expiration'] <= time()) {
            throw new \UnderflowException;
        }
        return parent::constructFromData($data, $updateMultitonStoreIfExists);
    }

    protected function get__title()
    {
        return $this->code;
    }

    // Disable all permisssions for guests
    public function disabledPermissions()
    {
        return [ \IPS\Settings::i()->guest_group => array_values(static::$permissionMap) ];
    }

    public function getButtons($url, $subnode = FALSE)
    {
        $buttons =  parent::getButtons($url, $subnode);
        $edit = $buttons['edit'];
        unset($buttons['edit']);

        $return = [$edit];
        $return['url'] = array(
            'icon'	=> 'globe',
            'title'	=> 'brilliantdiscord_invite_url',
            'link'	=> $this->url(),
            'target' => '_blank'
        );

        foreach ($buttons as $k => $v) $return[$k] = $v;
        return $return;
    }
}