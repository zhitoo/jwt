<?php

namespace Hshafiei374\Jwt;

use Illuminate\Http\Request;

class Guard
{
    //I should be a callable object
    public function __invoke(Request $request)
    {
        $jwt = resolve('jwt');
        return $jwt->getTokenableIfTokenValid($request);
    }

}
