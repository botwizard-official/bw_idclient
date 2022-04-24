<?php

namespace Idclient;

use Exception;

final class IdClientUtil {

    const ID_DOMAIN = 'https://id.botwizard.net';
    const OAUTH_URL = '%s/oauth2.php?x=%s&%s';

    private function __construct() {
        
    }

    public static function getCodeFlowAuthUrl($clientId, $redirectUri, $state) {

        $qs = http_build_query([
            'response_type' => 'code',
            'client_id' => intval($clientId),
            'redirect_uri' => strval($redirectUri),
            'state' => strval($state),
        ]);
        return sprintf(self::OAUTH_URL, self::ID_DOMAIN, 'authorize', $qs);
    }

    private static function getTokenEndpointUrl($domain) {
        return sprintf(self::OAUTH_URL, $domain, 'token', '');
    }

    private static function getUserinfoEndpointUrl($domain) {
        return sprintf(self::OAUTH_URL, $domain, 'userinfo', '');
    }

    private static function getIntrospectEndpointUrl($domain) {
        return sprintf(self::OAUTH_URL, $domain, 'introspect', '');
    }

    private static function doPost(
            $url, array $postbody, array $headers, $timeout) {
        ###var_dump($url);
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, strval($url));
        curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $postbody);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        $out = curl_exec($ch);
        curl_close($ch);
        return $out;
    }

    public static function doTokenReq($domain,
            array $postbody, $timeout) {
        $url = IdClientUtil::getTokenEndpointUrl($domain);
        $raw = self::doPost($url, $postbody, [], $timeout);
        $result = self::parseJson($raw);
        if (!empty($result['error'])) {
            throw new Exception($result['error_description'] ?? '');
        }
        return $result;
    }

    public static function doUserinfoReq($domain,
            $accessToken, $timeout) {
        $url = IdClientUtil::getUserinfoEndpointUrl($domain);
        $auth = sprintf('Authorization: Bearer %s', $accessToken);
        $raw = self::doPost($url, [], [$auth], $timeout);
        return self::parseJson($raw);
    }

    public static function doIntrospectReq($domain,
            array $postbody, $timeout) {
        $url = IdClientUtil::getIntrospectEndpointUrl($domain);
        $raw = self::doPost($url, $postbody, [], $timeout);
        return self::parseJson($raw);
    }

    private static function parseJson($raw) {
        $data = json_decode($raw, true);
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception(json_last_error_msg() . ':' . $raw);
        }
        return $data;
    }

    public static function codeGrantParams($clientId, $secret, $code) {
        return [
            'grant_type' => 'authorization_code',
            'client_id' => intval($clientId),
            'client_secret' => strval($secret),
            'code' => strval($code),
        ];
    }

    public static function refreshTokenGrantParams(
            $clientId, $secret, $refreshToken) {
        return [
            'grant_type' => 'refresh_token',
            'client_id' => intval($clientId),
            'client_secret' => strval($secret),
            'refresh_token' => strval($refreshToken),
        ];
    }

    public static function passwordGrantParams(
            $clientId, $secret, $username, $password) {
        return [
            'grant_type' => 'password',
            'client_id' => intval($clientId),
            'client_secret' => strval($secret),
            'username' => strval($username),
            'password' => strval($password),
        ];
    }

    public static function userinfoParams($accessToken) {
        return [
            'token' => strval($accessToken),
        ];
    }

    public static function introspectParams(
            $clientId, $secret, $accessToken) {
        return [
            'client_id' => intval($clientId),
            'client_secret' => strval($secret),
            'token' => strval($accessToken),
        ];
    }

}
