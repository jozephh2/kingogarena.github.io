<?php

namespace IPS\brilliantdiscord\modules\admin\manage;

/* To prevent PHP errors (extending class does not exist) revealing path */
if (!defined('\IPS\SUITE_UNIQUE_KEY')) {
    header((isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0') . ' 403 Forbidden');
    exit;
}

/**
 * logs
 */
class _logs extends \IPS\Dispatcher\Controller
{
    /**
     * Execute
     *
     * @return    void
     */
    public function execute()
    {
        \IPS\Dispatcher::i()->checkAcpPermission('brds_logs_manage');
        parent::execute();
    }

    /**
     * Manage
     *
     * @return    void
     */
    protected function manage()
    {
        /* Create the table */
        $table = new \IPS\Helpers\Table\Db('brilliantdiscord_logs', \IPS\Http\Url::internal('app=brilliantdiscord&module=manage&controller=logs'));

        $table->include = array('message', 'code', 'member', 'time');
        $table->mainColumn = 'message';
        $table->langPrefix = 'brilliantdiscord_logs_';

        $table->tableTemplate = array(\IPS\Theme::i()->getTemplate('tables', 'core', 'admin'), 'table');
        $table->rowsTemplate = array(\IPS\Theme::i()->getTemplate('tables', 'core', 'admin'), 'rows');

        $table->rowButtons = function ($row) {
            $return = array();

            $return['info'] = [
                'icon' => 'info-circle',
                'title' => 'brilliantdiscord_logs_info',
                'data' => ['ipsDialog' => '', 'ipsDialog-title' => \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_logs_info')],
                'link' => \IPS\Http\Url::internal('app=brilliantdiscord&module=manage&controller=logs&do=detailedInfo&id=') . $row['id'],
            ];

            return $return;
        };

        $table->parsers = array(
            'time' => function ($val, $row) {
                $t = \IPS\DateTime::ts($val);
                return $t->localeDate() . " " . $t->localeTime();
            },
            'member' => function ($val) {
                return \IPS\Member::load($val)->name;
            }
        );

        /* Default sort options */
        $table->sortBy = $table->sortBy ?: 'time';
        $table->sortDirection = $table->sortDirection ?: 'desc';

        /* Display */
        \IPS\Output::i()->title = \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_logs');
        \IPS\Output::i()->output = $table;
    }

    protected function detailedInfo()
    {
        try {
            $id = isset(\IPS\Request::i()->id) ? \IPS\Request::i()->id : NULL;
            if ($id == NULL || !is_numeric($id)) throw new \UnderflowException;
            $logs = json_decode(\IPS\Db::i()->select('exception_data', 'brilliantdiscord_logs', ['id=?', $id])->first(), TRUE);
        } catch (\UnderflowException $e) {
            \IPS\Output::i()->error('node_error', '1SBR106/1', 404);
        }
        \IPS\Output::i()->output = \IPS\Theme::i()->getTemplate('configuration', 'brilliantdiscord')->logDetailed($logs);
    }
}