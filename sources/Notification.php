<?php
namespace IPS\brilliantdiscord;

/* To prevent PHP errors (extending class does not exist) revealing path */

use IPS\brilliantdiscord\RateLimit\RateLimitedException;
use IPS\brilliantdiscord\Util\UnhandledDiscordException;

if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

class _Notification extends \IPS\Node\Model {

    protected static $multitons = [];
    public static $nodeTitle = 'brilliantdiscord_notifications';

    public static $databaseTable = 'brilliantdiscord_notifications';
    public static $databaseColumnOrder = 'position';

    protected static $formLangPrefix = 'brilliantdiscord_notifications_form_';
    protected static $conditionFormLangPrefix = 'brilliantdiscord_notifications_fcond_';

    protected static $additionalNotificationContent = [
        'nexus' => [
            'IPS\nexus\Support\Request',
            'IPS\nexus\Support\Reply'
        ]
        // todo add reports
    ];

    public function get__enabled() {
        return $this->enabled;
    }

    public function set__enabled($v) {
        $this->enabled = (bool) $v;
    }

    public function setDefaultValues()
    {
        parent::setDefaultValues();
        $this->conditions = NULL;
    }

    public static function webhooks()
    {
        $gid = \IPS\Settings::i()->brilliantdiscord_guild;
        if (!isset(\IPS\Data\Store::i()->discord_webhooks) || \IPS\Data\Store::i()->discord_webhooks['timestamp'] + 30  < time()) {
            $channels = RateLimit::limitHandle('guilds/{guild.id}/channels', $gid, function ($check) use ($gid) {
                $request = new Request("guilds/$gid/channels");
                $request->applyDefaultHeaders();
                $request->bot();
                $response = $request->submit();
                $check($response);
                if ($response->httpResponseCode != 200) {
                    throw new UnhandledDiscordException($request, $response);
                }
                return array_filter($response->decodeJson(), function ($v) {
                    return $v['type'] == 0;
                });
            });
            $webhooks = RateLimit::limitHandle('guilds/{guild.id}/webhooks', $gid, function ($check) use ($gid) {
                $request = new Request("guilds/$gid/webhooks");
                $request->applyDefaultHeaders();
                $request->bot();
                $response = $request->submit();
                $check($response);
                switch ($response->httpResponseCode) {
                    case 200:
                        break;
                    case 403:
                        throw new \OutOfRangeException;
                        break;
                    default:
                        throw new UnhandledDiscordException($request, $response);
                        break;
                }
                return $response->decodeJson();
            });
            $result = [];
            foreach ($channels as $v) $result[$v['id']] = [
                '__create_new_' . $v['id'] => '__new_webhook__'
            ];
            foreach ($webhooks as $webhook) $result[$webhook['channel_id']][$webhook['id'] . '/' .$webhook['token']] = $webhook['name'];
            $realresult = [];
            foreach ($channels as $v) $realresult["#{$v['name']} ({$v['id']})"] = $result[$v['id']];
            \IPS\Data\Store::i()->discord_webhooks = [
                'timestamp' => time(),
                'webhooks' => $realresult
            ];
        }
        return \IPS\Data\Store::i()->discord_webhooks['webhooks'];
    }

    public function form(&$form)
    {
        \IPS\Output::i()->cssFiles = array_merge( \IPS\Output::i()->cssFiles, \IPS\Theme::i()->css( 'general/misc.css', 'brilliantdiscord', 'admin' ) );

        $p = static::$formLangPrefix;
        $form->addHeader($p.'settings');
        $form->add( new \IPS\Helpers\Form\Text($p.'name', $this->id ? $this->name : NULL, TRUE, ['maxLength' => 255] ) );
        try {
            $webhooks = static::webhooks();
            foreach ($webhooks as $k => $w) {
                foreach ($w as $kk => $x) {
                    $webhooks[$k][$kk] = \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_webhook_new');
                    break;
                }
            }
            $form->add( new \IPS\Helpers\Form\Select($p.'webhook', $this->id ? $this->webhook : NULL, TRUE, [
                'parse' => 'normal',
                'options' => $webhooks
            ]));
        } catch (RateLimitedException $e) {
            $form->addDummy($p.'webhook', $e->ipsMessage());
        } catch (UnhandledDiscordException $e) {
            $e->safeHandle(TRUE, '5SBR104/1');
        } catch (\OutOfRangeException $e) {
            \IPS\Output::i()->error('brilliantdiscord_webhooks_noperm', '4SBR104/1', 500);
        }
        $classes = [NULL => ''];
        foreach (\IPS\Content::routedClasses(FALSE, FALSE, FALSE) as $v) {
            $classes[$v] = \IPS\Member::loggedIn()->language()->addToStack($v::$title) . " ($v)";
        }
        foreach (static::$additionalNotificationContent as $k => $v) {
            if (\IPS\Application::appIsEnabled($k)) {
                foreach ($v as $vv) {
                    $classes[$vv] = \IPS\Member::loggedIn()->language()->addToStack($vv::$title) . " ($vv)";
                }
            }
        }
        $form->add( new \IPS\Helpers\Form\Select($p.'item_class', $this->id ? $this->item_class : NULL, TRUE, [
            'parse' => 'normal',
            'options' => $classes,
        ]) );

        $form->add( new \IPS\Helpers\Form\Radio($p.'instant_post', $this->id ? $this->instant_post : 0, NULL, [
            'options' => [
                TRUE => $p . 'instant_post_instant',
                FALSE => $p . 'instant_post_late',
            ]
        ]) );

        $form->addHeader($p.'display');
        $form->add( new \IPS\Helpers\Form\Radio($p.'message_type', $this->id ? $this->notification_settings['type'] : 'embed', TRUE, [
            'options' => [
                'message' => $p.'msgtype_basic',
                'embed' => $p.'msgtype_embed',
            ],
            'toggles' => [
                'message' => ['message'],
                'embed' => ['max_characters', 'embed_color', 'category_lang', 'embed_title']
            ]
        ]) );

        $tags = ['url', 'title', 'author'];
        $real_tags = [];
        foreach ($tags as $t) $real_tags['${' . "$t}"] = \IPS\Member::loggedIn()->language()->addToStack('brilliantdiscord_form_tag_'.$t);
        $form->add( new \IPS\Helpers\Form\TextArea($p.'message', ($this->id && $this->notification_settings['type'] == 'message') ? $this->notification_settings['message'] : NULL, TRUE, [
            'maxLength' => 2000,
            'tags' => $real_tags,
            'class' => 'ipsField_codeInput brdsMessageFieldSize'
        ], function($val) {
            if (trim($val) == '') throw new \DomainException('form_required');
        }, NULL, NULL, 'message') );
        unset (\IPS\Request::i()->cookie['tagSidebar']);

        $form->add( new \IPS\Helpers\Form\Text($p.'embed_title', ($this->id && $this->notification_settings['type'] == 'embed') ? $this->notification_settings['title'] : '${title}', TRUE, [], NULL, NULL, NULL, 'embed_title') );
        $form->add( new \IPS\Helpers\Form\Number($p.'max_characters', ($this->id && $this->notification_settings['type'] == 'embed') ? $this->notification_settings['size'] : 160, NULL, [
            'min' => 3,
            'max' => 1024
        ], NULL, NULL, NULL, 'max_characters' ));
        $form->add( new \IPS\Helpers\Form\Color($p.'embed_color', ($this->id && $this->notification_settings['type'] == 'embed') ? $this->notification_settings['color'] : '7289da', NULL, [], NULL, NULL, NULL, 'embed_color') );
        $lang = NULL;
        if ($this->id && $this->notification_settings['type'] == 'embed') {
            if ($this->notification_settings['catlang'] == 0) {
                $lang = 0;
            } else {
                try {
                    $lang = \IPS\Lang::load($this->notification_settings['catlang']);
                } catch (\OutOfRangeException $e) {
                    $lang = 0;
                }
            }
        } else {
            $lang = 0;
        }
        $form->add( new \IPS\Helpers\Form\Node($p.'category_lang', $lang, NULL, [
            'class' => \IPS\Lang::class,
            'zeroVal' => $p.'default_lang',
        ], NULL, NULL, NULL, 'category_lang' ));
    }

    public function formatFormValues($values)
    {
        $prefixLength = mb_strlen(static::$formLangPrefix);
        foreach ($values as $k => $v) {
            if (mb_substr($k, 0, $prefixLength) == static::$formLangPrefix) {
                unset($values[$k]);
                $values[mb_substr($k, $prefixLength)] = $v;
            }
        }
        if (mb_substr($values['webhook'], 0, 13) == '__create_new_') {
            try {
                $cid = mb_substr($values['webhook'], 13);
                $values['webhook'] = RateLimit::limitHandle('channels/{channel.id}/webhooks', $cid, function($check) use ($values, $cid) {
                    $request = new Request("channels/$cid/webhooks");
                    $request->applyDefaultHeaders();
                    $request->bot();
                    $response = $request->submit('POST', json_encode([
                        'name' => mb_substr($values['name'], 0, 32)
                    ]));
                    $check($response);
                    if ($response->httpResponseCode == 400) {
                        \IPS\Output::i()->error('brilliantdiscord_error_whlimit', '5SBR100/2');
                    }
                    if ($response->httpResponseCode != 200) (new UnhandledDiscordException($request, $response))->safeHandle(TRUE, '5SBR105/1');
                    $json = $response->decodeJson();
                    return $json['id'].'/'.$json['token'];
                });
                unset(\IPS\Data\Store::i()->discord_webhooks);
            } catch (RateLimitedException $e) {
                \IPS\Output::i()->error($e->ipsMessage(), '1SBR100/1');
            }
        }
        return $values;
    }

    public function saveForm($values)
    {
        if ($this->_new) $this->_data['enabled'] = TRUE;
        if ($values['message_type'] == 'embed') {
            $this->notification_settings = [
                'type' => 'embed',
                'size' => $values['max_characters'],
                'color' => mb_substr($values['embed_color'], 1),
                'catlang' => $values['category_lang'] == 0 ? 0 : $values['category_lang']->_id,
                'title' => $values['embed_title']
            ];
        } else {
            $this->notification_settings = [
                'type' => 'message',
                'message' => $values['message']
            ];
        }
        $this->instant_post = (bool) $values['instant_post'];
        foreach (['message_type', 'message', 'max_characters', 'embed_color', 'category_lang', 'embed_title', 'instant_post'] as $k) unset($values[$k]);
        parent::saveForm($values);
    }

    public function get_notification_settings()
    {
        return json_decode($this->_data['notification_settings'], TRUE);
    }

    public function set_notification_settings($value)
    {
        $this->_data['notification_settings'] = json_encode($value);
    }

    public function get_conditions()
    {
        if ($this->_data['conditions'] == NULL) return NULL;
        return json_decode($this->_data['conditions'], TRUE);
    }

    public function set_conditions($value)
    {
        $this->_data['conditions'] = $value == NULL ? NULL : json_encode($value);
    }

    public function url()
    {
        return NULL;
    }

    public function get__title()
    {
        return $this->name;
    }

    /**
     * Check if content applies to a notification
     *
     * @param $item \IPS\Content\Comment|\IPS\Content\Review|\IPS\Content\Item Content item to check
     * @param $wasHidden bool If the item was hidden before
     * @return bool
     */
    public function contentApplies($item, $wasHidden=FALSE)
    {
        if (static::isInClub($item)) return FALSE;

        if ($this->instant_post) {
            if ($wasHidden) return FALSE;
        } else {
            if ($item->hidden() !== 0) return FALSE;
        }

        // Prevent sending two notifications for a topic (for a topic and for a post)
        if ($item instanceof \IPS\Content\Comment && $item->isFirst()) return FALSE;

        // Check conditions
        $conditions = $this->conditions;
        if ($conditions == NULL) return TRUE;

        if (isset($conditions['content'])) {
            $subitem = $item->item();
            if (!\in_array($subitem->{$subitem::$databaseColumnId}, explode(',', $conditions['content']))) {
                return FALSE;
            }
        }
        if (isset($conditions['author']) && !\in_array($item->author()->member_id, explode("\n", $conditions['author']))) return FALSE;

        $categoryItem = (!$item instanceof \IPS\Content\Item) ? $item->item() : $item;
        $container = $categoryItem instanceof \IPS\nexus\Support\Request ? $categoryItem->department : $categoryItem->container();
        if (isset($conditions['category']) && !\in_array($container->_id, explode(",", $conditions['category']))) return FALSE;
        // todo another conditions in notifications
        return TRUE;
    }

    /**
     * Send notification for content
     *
     * @param $item \IPS\Content\Comment|\IPS\Content\Review|\IPS\Content\Item New content item
     */
    public function sendNotification($item)
    {
        /**
         * @var $targetContentItem \IPS\Content\Item
         */
        $isItem = $item instanceof \IPS\Content\Item;
        $targetContentItem = $isItem ? $item : $item->item();
        $request = new Request('webhooks/'.$this->webhook);
        $request->applyDefaultHeaders();
        $settings = $this->notification_settings;
        if ($settings['type'] == 'embed') {
            $embedContent = trim(
                str_replace(
                    '&nbsp;',
                    ' ',
                    strip_tags(
                        $this->formatContent(preg_replace('/[\r\n\f]+/m', '', preg_replace(
                            '#(<(script|style)\b[^>]*>).*?(</\2>)#is',
                            "$1$3",
                            $item->content()
                        )))
                    )
                )
            );

            if (mb_strlen($embedContent) > $settings['size']) {
                $embedContent = mb_substr($embedContent, 0, $settings['size'] - 3) . '...';
            }
        }
        $parentStack = $this->parentStackGenerate($targetContentItem);
        $parents = $parentStack ? ' • ' . $parentStack : NULL;
        if ($settings['type'] == 'embed') {
            $body = [
                'embeds' => [
                    [
                        'color' => hexdec($settings['color']),
                        'title' => str_replace('${title}', $targetContentItem->mapped('title'), $settings['title']),
                        'description' => $embedContent,
                        'timestamp' => date("c", $item->mapped('date')),
                        'footer' => [
                            'text' => $item->author()->real_name . $parents,
                        ]
                    ]
                ]
            ];
            // Set URL for...
            switch (\get_class($item)) {
                case 'IPS\nexus\Support\Request':
                    $body['embeds'][0]['url'] = (string) $item->acpUrl();
                    break;
                case 'IPS\nexus\Support\Reply':
                    $body['embeds'][0]['url'] = (string) $item->item()->acpUrl();
                    break;
                default:
                    // Otherwise, make it default
                    $body['embeds'][0]['url'] = (string) $item->url();
            }
            // no 4.4 svg avatars, todo support 4.4 avatars svg
            $photoUrl = $item->author()->get_photo(TRUE, FALSE);
            if (\IPS\Application::load('core')->long_version >= 104000) {
                if (mb_substr($photoUrl, 0, 14) == 'data:image/svg') {
                    $photoUrl = NULL;
                }
            }
            if ($photoUrl != NULL) {
                $photoUrl = (string) $photoUrl;
                if (mb_substr($photoUrl, 0, 2) == '//') {
                    $photoUrl = (mb_substr(\IPS\Settings::i()->base_url, 0, 5) == 'https') ? ('https:' . $photoUrl) : ('http:' . $photoUrl);
                }
                $body['embeds'][0]['footer']['icon_url'] = $photoUrl;
            }
        }
        $response = $request->submit('POST', json_encode($settings['type'] == 'embed' ? $body : [
            'content' =>
                strtr(
                    $settings['message'], [
                        '${author}' => $this->escapeContent($item->author()->name),
                        '${title}' => $this->escapeContent($targetContentItem->mapped('title')),
                        '${url}' => (string) (mb_substr(\get_class($item), 0, 17) == 'IPS\nexus\Support' ? $item->acpUrl() : $item->url()),
                    ]
                )
        ]));
        if (!\in_array($response->httpResponseCode, [200, 204])) (new UnhandledDiscordException($request, $response))->safeHandle(FALSE);
    }

    protected function parentStackGenerate($item) {
        try {
            $lid = $this->notifcation_settings['catlang'] ?: \IPS\Lang::defaultLanguage();
            $lang = \IPS\Lang::load($lid);
        } catch ( \OutOfRangeException $e ) {
            $lang = \IPS\Lang::load(\IPS\Lang::defaultLanguage());
        }
        $parents = [];
        $container = \get_class($item) == 'IPS\nexus\Support\Request' ? $item->department : $item->containerWrapper();
        while ($container != NULL) {
            $parents[] = $lang->get($container::$titleLangPrefix . $container->_id);
            $container = $container->parent();
        }
        if (!$parents) return NULL;
        return implode(' → ', array_reverse($parents));
    }

    /**
     * Check if item is in a club
     *
     * @param \IPS\Content\Review|\IPS\Content\Comment|\IPS\Content\Item $item Item to check
     */
    protected static function isInClub($item)
    {
        if (!($item instanceof \IPS\Content\Item)) {
            $item = $item->item();
        }
        $container = $item->containerWrapper();
        if ($container != NULL &&
            \IPS\IPS::classUsesTrait(\get_class($container), \IPS\Content\ClubContainer::class) &&
            $container->club()
        ) {
            return;
        }
    }

    public static function parseContent($class, $item, $wasHidden=FALSE)
    {
        foreach (new \IPS\Patterns\ActiveRecordIterator(
                     \IPS\Db::i()->select('*', 'brilliantdiscord_notifications', ['`enabled`=1 AND `item_class`=?', $class]),
                     Notification::class
                 ) as $notification) {
            if ($notification->contentApplies($item, $wasHidden)) {
                $notification->sendNotification($item);
            }
        }
    }

    public function conditionForm(&$form)
    {
        $p = static::$conditionFormLangPrefix;
        $conditions = $this->conditions ?: [];
        $class = $this->item_class;
        $_parents = class_parents($class);
        $canLimitToContent = \in_array('IPS\Content\Comment', $_parents) || \in_array('IPS\Content\Review', $_parents);
        $realItemClass = $canLimitToContent ? $class::$itemClass : $class;
        $canLimitToCategory = isset($realItemClass::$containerNodeClass);

        if ($canLimitToContent) {
            $form->add( new \IPS\Helpers\Form\YesNo($p.'check_content', isset($conditions['content']) ? TRUE : FALSE, FALSE, [
                'togglesOn' => ['content'],
                'togglesOff' => ['author', 'category', '_cc_author', '_cc_category']
            ] ));
            $form->add( new \IPS\Helpers\Form\Item($p.'content', isset($conditions['content']) ? $conditions['content'] : [], NULL, [
                'class' => $realItemClass
            ], NULL, NULL, NULL, 'content' ) );
        } else {
            $form->hiddenValues[$p.'check_content'] = 0;
        }

        $form->add( new \IPS\Helpers\Form\YesNo($p.'check_author', isset($conditions['author']) ? TRUE : FALSE, FALSE, [
            'togglesOn' => ['author']
        ], NULL, NULL, NULL, '_cc_author' ));
        if ($conditions['author']) $authors = array_filter(array_map(function($id) {
            $member = \IPS\Member::load($id);
            return (!$member->member_id) ? NULL : $member;
        }, explode("\n", $conditions['author'])), function($m) {
            return $m !== NULL;
        });
        $form->add( new \IPS\Helpers\Form\Member($p.'author', isset($conditions['author']) ? $authors : [], NULL, [
            'multiple' => NULL,
        ], NULL, NULL, NULL, 'author' ) );

        if ($canLimitToCategory) {
            $form->add( new \IPS\Helpers\Form\YesNo($p.'check_category', isset($conditions['category']) ? TRUE : FALSE, FALSE, [
                'togglesOn' => ['category']
            ], NULL, NULL, NULL, '_cc_category' ));
            $form->add( new \IPS\Helpers\Form\Node($p.'category', isset($conditions['category']) ? $conditions['category'] : [], NULL, [
                'class' => $realItemClass::$containerNodeClass,
                'multiple' => TRUE,
            ], NULL, NULL, NULL, 'category' ) );
        } else {
            $form->hiddenValues[$p.'check_category'] = 0;
        }
    }

    public function saveConditionForm(&$form, $values)
    {
        $conditions = [];
        $lenofpref = mb_strlen(static::$conditionFormLangPrefix);
        foreach ($values as $k => $v) {
            if (mb_substr($k, 0, $lenofpref) == static::$conditionFormLangPrefix) {
                unset($values[$k]);
                $values[mb_substr($k, $lenofpref)] = $v;
            }
        }
        $p = static::$conditionFormLangPrefix;
        if ($values['check_content']) {
            if (!$values['content']) {
                $form->elements[''][$p.'content']->error = \IPS\Member::loggedIn()->language()->addToStack('form_required');
                return FALSE;
            }
            $conditions['content'] = \IPS\Helpers\Form\Item::stringValue($values['content']);
        } else {
            if ($values['check_category']) {
                if (!$values['category']) {
                    $form->elements[''][$p.'category']->error = \IPS\Member::loggedIn()->language()->addToStack('form_required');
                    return FALSE;
                }
                $conditions['category'] = \IPS\Helpers\Form\Node::stringValue($values['category']);
            }
            if ($values['check_author']) {
                if (!$values['author']) {
                    $form->elements[''][$p.'author']->error = \IPS\Member::loggedIn()->language()->addToStack('form_required');
                    return FALSE;
                }
                $conditions['author'] = \IPS\Helpers\Form\Member::stringValue($values['author']);
            }
        }
        $this->conditions = $conditions ? $conditions : NULL;
        $this->save();
        return TRUE;
    }

    public function getButtons($url, $subnode = FALSE)
    {
        $buttons = parent::getButtons($url, $subnode);

        // Move the delete and copy button at the end
        $delete = $buttons['delete'];
        $copy = $buttons['copy'];
        unset($buttons['copy']);
        unset($buttons['delete']);

        $buttons['conditions'] = array(
            'icon'	=> 'cogs',
            'title'	=> 'brilliantdiscord_notifications_conditions',
            'link'	=> $url->setQueryString( array( 'do' => 'conditions', 'id' => $this->_id ) )
        );

        $buttons['copy'] = $copy;
        $buttons['delete'] = $delete;
        return $buttons;
    }

    protected function escapeContent($text)
    {
        foreach ([
            '`' => '\\`',
            '@everyone' => '`@everyone`',
            '@here' => '`@here`',
            '<@' => '<\@',
        ] as $k => $v) {
            $text = strtr($text, [$k => $v]);
        }
        return $text;
    }

    protected function formatContent($text)
    {
        // todo see embed-formatting branch
        return $text;
    }
}