<?php

namespace Zhitoo\Jwt;


trait HasApiTokens
{
    public function createToken()
    {
        $jwt = JWT::getInstance(config('jwt.expiration'), config('jwt.secret'));
        //create a unique token for user
        while (true) {
            $token = $jwt->createToken(request(), $this);
            $tokenRow = $this->tokens()->where('token', hash('sha256', $token))->first();
            if (!$tokenRow) {
                $this->tokens()->create([
                    'token' => hash('sha256', $token),
                ]);
                break;
            }
        }
        return $token;
    }

    /**
     * Get the access tokens that belong to model.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphMany
     */
    public function tokens()
    {
        return $this->morphMany(JWT::$JwtTokenModel, 'tokenable');
    }

}
