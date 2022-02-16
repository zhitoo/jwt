<?php

namespace Hshafiei374\Jwt;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Log;

class JwtToken extends Model
{

    protected $table = 'jwt_tokens';
    /**
     * The attributes that should be cast to native types.
     *
     * @var array
     */
    protected $casts = [
        'last_used_at' => 'datetime',
    ];

    /**
     * The attributes that are mass assignable.
     *
     * @var array
     */
    protected $fillable = [
        'token'
    ];

    /**
     * The attributes that should be hidden for serialization.
     *
     * @var array
     */
    protected $hidden = [
        'token',
    ];

    /**
     * Get the tokenable model that the access token belongs to.
     *
     * @return \Illuminate\Database\Eloquent\Relations\MorphTo
     */
    public function tokenable()
    {
        return $this->morphTo('tokenable');
    }

    /**
     * Find the token instance matching the given token.
     *
     * @param string $token
     * @return static|null
     */
    public static function findToken($token)
    {
        return static::where('token', hash('sha256', $token))->first();
    }

    public static function updateLastUsedAt($token)
    {
        $token = static::findToken($token);
        $token->last_used_at = Carbon::now();
        return $token->save();
    }

    public static function isTokenValid($token)
    {
        return static::findToken($token)->is_valid;
    }

    public static function blockToken($token)
    {
        $token = static::findToken($token);
        $token->is_valid = false;
        return $token->save();
    }

}
