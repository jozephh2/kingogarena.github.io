<?php

namespace IPS\brilliantdiscord;

/* To prevent PHP errors (extending class does not exist) revealing path */
if ( !defined( '\IPS\SUITE_UNIQUE_KEY' ) )
{
	header( ( isset( $_SERVER['SERVER_PROTOCOL'] ) ? $_SERVER['SERVER_PROTOCOL'] : 'HTTP/1.0' ) . ' 403 Forbidden' );
	exit;
}

class _CdnUtil {
    const CDN_BASE = 'https://cdn.discordapp.com/';

    /**
     * Prepare avatar's URL
     *
     * @param string $id User's ID
     * @param string $hash Avatar hash
     * @param string $format jpg, jpeg, png, webp. Defaults to png.
     * @param bool $animated When true, returns GIF, if avatar is animated
     * @return \IPS\Http\Url|NULL
     */
    public static function avatar($id, $hash, $format = 'png', $animated = FALSE) {
        if ($hash == NULL) return NULL;
        if ($animated && mb_substr($hash, 0, 2) == 'a_') {
            $format = 'gif';
        }
        return \IPS\Http\Url::external(static::CDN_BASE . "avatars/$id/$hash.$format");
    }

    /**
     * User's default avatar URL. (format is PNG)
     *
     * @param int $discriminator User's discriminator
     * @return \IPS\Http\Url
     */
    public static function defaultAvatar($discriminator) {
        $discriminator = $discriminator % 5;
        return \IPS\Http\Url::external(static::CDN_BASE . "embed/avatars/$discriminator.png");
    }

    /**
     * Prepare icon's URL
     *
     * @param string $gid Guild ID
     * @param string $icon Icon hash
     * @param string $format jpg, jpeg, png, webp. Defaults to png.
     * @return \IPS\Http\Url|NULL
     */
    public static function guildIcon($gid, $icon, $format = 'png') {
        if ($icon == NULL) return NULL;
        return \IPS\Http\Url::external(static::CDN_BASE . "icons/$gid/$icon.$format");
    }

    /**
     * Application's icon.
     *
     * @param string $id Application's id
     * @param string $icon Icon hash
     * @param string $format jpg, jpeg, png, webp. Defaults to png.
     * @return \IPS\Http\Url|null
     */
    public static function appIcon($id, $icon, $format = 'png') {
        if ($icon == NULL) return NULL;
        return \IPS\Http\Url::external(static::CDN_BASE . "app-icons/$id/$icon.$format");
    }

    // Stupid IPS.
    protected final function dummy() {}
}