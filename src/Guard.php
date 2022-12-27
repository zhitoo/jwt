<?php

namespace Zhitoo\Jwt;

use Illuminate\Http\Request;

class Guard
{
    //I should be a callable object
    public function __invoke(Request $request)
    {
        return JWT::getInstance()->getTokenableIfTokenValid($request);
    }

}
