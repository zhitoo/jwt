<?php

namespace Hshafiei374\Jwt;

use Illuminate\Http\Request;

class Guard
{
    private $secret;
    private $expiration;

    public function __construct(int $expiration, string $secret)
    {
        $this->expiration = $expiration * 60;//change minutes to seconds
        $this->secret = $secret;
    }

    //I should be a callable object
    public function __invoke(Request $request)
    {
        return JWT::getInstance($this->expiration, $this->secret)->getTokenableIfTokenValid($request);
    }

}
