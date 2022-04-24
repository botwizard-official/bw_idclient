<?php

namespace Idclient;

use Exception;

final class OauthCookie {

    private const OAUTH_STATE = 'state';
    private const OAUTH_ACCESS_TOKEN = 'access_token';
    private const OAUTH_REFRESH_TOKEN = 'refresh_token';

    public static function setState($value, $expires) {
        self::set(self::OAUTH_STATE, strval($value), $expires);
    }

    public static function setAccessToken($value, $expires) {
        self::set(self::OAUTH_ACCESS_TOKEN, strval($value), $expires);
    }

    public static function setRefreshToken($value, $expires) {
        self::set(self::OAUTH_REFRESH_TOKEN, strval($value), $expires);
    }

    public static function getState() {
        return strval(self::get(self::OAUTH_STATE));
    }

    public static function getAccessToken() {
        return strval(self::get(self::OAUTH_ACCESS_TOKEN));
    }

    public static function getRefreshToken() {
        return strval(self::get(self::OAUTH_REFRESH_TOKEN));
    }

    public static function setFromTokenResult($result) {
        self::setAccessToken($result['access_token'],
                time() + $result['expires_in']);
        if ($result && !empty($result['refresh_token'])) {
            self::setRefreshToken($result['refresh_token'],
                    strtotime('+1 month'));
            // TODO refresh_token expires_in ?
        }
    }

    private static function set($name, $value, $expires) {
        $host = strval(filter_input(INPUT_SERVER, 'HTTP_HOST'));
        $opts = [
            'expires' => $expires,
            'path' => '/',
            'domain' => '.' . $host,
            'secure' => true,
            'httponly' => true,
            'samesite' => 'None' // None || Lax || Strict
        ];
        if (!setcookie($name, $value, $opts)) {
            throw new Exception('unable to set oauth cookie');
        }
    }

    private static function get($name) {
        return strval($_COOKIE[$name] ?? '');
    }

}
