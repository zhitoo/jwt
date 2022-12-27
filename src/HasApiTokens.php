<?php

namespace Zhitoo\Jwt;


trait HasApiTokens
{
    public function createToken()
    {
        return JWT::getInstance()->createToken(request(), $this);
    }

}
