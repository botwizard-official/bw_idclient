<?php

namespace Idclient;

use Exception;

class IdClient {

    /**
     *
     * @var string
     */
    protected $idDomain;

    /**
     *
     * @var int
     */
    protected $clientId;

    /**
     *
     * @var string
     */
    protected $clientSecret;

    /**
     *
     * @var int
     */
    protected $timeout;

    /**
     *
     * @var Cache
     */
    protected $userinfoCache;

    /**
     *
     * @var Cache
     */
    protected $introspectCache;

    public function __construct($timeout = 30) {
        $this->setClientId(0)
                ->setClientSecret('')
                ->setTimeout(intval($timeout))
                ->setIdDomain(IdClientUtil::ID_DOMAIN);
    }

    /**
     * Get authorize page URL to redirect a visitor.
     * 
     * @param string $redirectUri
     * @param string $state
     * @return string
     */
    public function getCodeFlowAuthUrl($redirectUri, $state = '') {
        return IdClientUtil::getCodeFlowAuthUrl($this->getClientId(),
                        $redirectUri, $state);
    }

    /**
     * Exchange authorization code.
     * 
     * @param string $code
     * @return array
     */
    public function exchangeCode($code) {
        $postbody = IdClientUtil::codeGrantParams($this->getClientId(),
                        $this->getSecret(), strval($code));
        return IdClientUtil::doTokenReq($this->getIdDomain(),
                        $postbody, $this->getTimeout());
    }

    /**
     * Obtain new access token using "refresh token".
     * 
     * @param string $refreshToken
     * @return array
     */
    public function refreshToken($refreshToken) {
        $postbody = IdClientUtil::refreshTokenGrantParams($this->getClientId(),
                        $this->getSecret(), strval($refreshToken));
        return IdClientUtil::doTokenReq($this->getIdDomain(),
                        $postbody, $this->getTimeout());
    }

    /**
     * Get access token by credentials.
     * 
     * @param string $username
     * @param string $password
     * @return array
     */
    public function signIn($username, $password) {
        $postbody = IdClientUtil::passwordGrantParams($this->getClientId(),
                        $this->getSecret(),
                        strval($username), strval($password));
        return IdClientUtil::doTokenReq($this->getIdDomain(),
                        $postbody, $this->getTimeout());
    }

    /**
     * Return's User info.
     * 
     * @param string $accessToken
     * @return array
     */
    public function getUserinfo($accessToken) {
        $cache = $this->getUserinfoCache();
        if ($cache && is_array(($result = $cache->get($accessToken)))) {
            return $result;
        }
        $result = IdClientUtil::doUserinfoReq($this->getIdDomain(),
                        strval($accessToken),
                        $this->getTimeout());
        if (!isset($result['user_id'])) {
            throw new Exception('bad userinfo result');
        }
        if ($cache) {
            $cache->set($accessToken, $result);
        }
        return $result;
    }

    /**
     * Retrieive Full information about given Token.
     * 
     * @param string $accessToken
     * @return array
     */
    public function introspect($accessToken) {
        $cache = $this->getIntrospectCache();
        if ($cache && is_array(($result = $cache->get($accessToken)))) {
            return $result;
        }
        $postbody = IdClientUtil::introspectParams($this->getClientId(),
                        $this->getSecret(), strval($accessToken));
        $result = IdClientUtil::doIntrospectReq($this->getIdDomain(),
                        $postbody, $this->getTimeout());
        if (!isset($result['active'])) {
            throw new Exception('bad tokeninfo result');
        }
        if ($cache) {
            $cache->set($accessToken, $result);
        }
        if (empty($result['active'])) {
            throw new Exception('inactive token');
        }
        return $result;
    }

    public function getClientId() {
        return $this->clientId;
    }

    public function getSecret() {
        return $this->clientSecret;
    }

    public function setClientId($clientId) {
        $this->clientId = $clientId;
        return $this;
    }

    public function setClientSecret($clientSecret) {
        $this->clientSecret = $clientSecret;
        return $this;
    }

    public function getTimeout() {
        return $this->timeout;
    }

    public function setTimeout($timeout) {
        $this->timeout = $timeout;
        return $this;
    }

    public function getUserinfoCache(): ?Cache {
        return $this->userinfoCache;
    }

    public function setUserinfoCache(Cache $userinfoCache) {
        $this->userinfoCache = $userinfoCache;
        return $this;
    }

    public function getIntrospectCache(): ?Cache {
        return $this->introspectCache;
    }

    public function setIntrospectCache(Cache $introspectCache) {
        $this->introspectCache = $introspectCache;
        return $this;
    }

    public function getIdDomain() {
        return $this->idDomain;
    }

    public function setIdDomain($idDomain) {
        $this->idDomain = $idDomain;
        return $this;
    }

}
