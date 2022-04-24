<?php

namespace Idclient;

use Exception;

final class OauthComponent {

    /**
     *
     * @var IdClient
     */
    protected $idClient;

    /**
     *
     * @var string
     */
    protected $accessToken;

    public function __construct(IdClient $idClient) {
        $this->idClient = $idClient;
        $this->accessToken = OauthCookie::getAccessToken();
    }

    /**
     * 
     * @param string $redirectUri
     * @return boolean
     * @throws Exception
     */
    public function process($redirectUri) {
        $oauthCodeArg = strval(filter_input(INPUT_GET, 'code'));
        $oauthStateArg = strval(filter_input(INPUT_GET, 'state'));
        $oauthStateCookie = OauthCookie::getState();
        $refreshToken = OauthCookie::getRefreshToken();

        if (empty($this->getAccessToken())) {
            if (!empty($refreshToken)) {
                //refresh token
                $result = $this->idClient->refreshToken($refreshToken);

                $this->accessToken = strval($result['access_token']);
                #OauthCookie::setFromTokenResult($result);
            } elseif (empty($oauthCodeArg)) {
                $oauthStateRand = sha1(random_bytes(64));

                $url = $this->idClient
                        ->getCodeFlowAuthUrl($redirectUri, $oauthStateRand);
                header('location: ' . $url, true, 302);
                OauthCookie::setState($oauthStateRand,
                        strtotime('+2 minutes'));
                $this->erase(false, true);
                return false;
            } elseif (!empty($oauthCodeArg)) {

                if (0 !== strcmp($oauthStateArg, $oauthStateCookie)) {
                    throw new Exception('invalid oauth state');
                }

                $result = $this->idClient->exchangeCode($oauthCodeArg);

                $this->accessToken = strval($result['access_token']);

                header('location: ' . $redirectUri, true, 302);
                $this->erase(true, false);
                OauthCookie::setFromTokenResult($result);
                return false;
            }
        }
        return true;
    }

    public function getAccessToken(): string {
        return $this->accessToken;
    }

    public function erase($state, $tokens) {
        if ($state) {
            OauthCookie::setState('', 0);
        }
        if ($tokens) {
            OauthCookie::setAccessToken('', 0);
            OauthCookie::setRefreshToken('', 0);
        }
    }

}
