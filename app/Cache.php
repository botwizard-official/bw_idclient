<?php

namespace Idclient;

interface Cache {

    public function get($accessToken);

    public function set($accessToken, $result);
}
