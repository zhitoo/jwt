<?php

namespace Zhitoo\Jwt;


trait HasApiTokens
{
    private string $token;

    public function createToken(): string
    {
        $this->token = JWT::getInstance()->createToken(request(), $this);
        return $this->token;
    }

    /**
     * @return void
     */
    public function revokeAccessToken()
    {
        $jwt = JWT::getInstance();
        $jwt->addTokenToBlackList($this->token ?? $jwt->getTokenFromRequest(request()));
    }

    /**
     * @return string
     */
    public function currentAccessToken(): string
    {
        $jwt = JWT::getInstance();
        return $this->token ?? $jwt->getTokenFromRequest();
    }

}
