<?php
return [
    /*
    |--------------------------------------------------------------------------
    | Salt value
    |--------------------------------------------------------------------------
    |
    */
    'secret' => env('JWT_SECRET', 'secret_key'),

    'blacklist_path' => storage_path() . '/jwt/blacklist',

    /*
    |--------------------------------------------------------------------------
    | Expiration Minutes
    |--------------------------------------------------------------------------
    |
    | This value controls the number of minutes until an issued token will be
    | considered expired.
    |
    */

    'expiration' => 1,
];
