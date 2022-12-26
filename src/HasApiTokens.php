<?php

namespace Zhitoo\Jwt;


trait HasApiTokens
{
    public function createToken()
    {
        $jwt = JWT::getInstance(config('jwt.expiration'), config('jwt.secret'));
        return $jwt->createToken(request(), $this);
    }

}
