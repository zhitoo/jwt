<?php

namespace Hshafiei374\Jwt;

use Illuminate\Auth\RequestGuard;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\ServiceProvider;

class JWTServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     *
     * @return void
     */
    public function register()
    {
        config([
            'auth.guards.jwt' => array_merge([
                'driver' => 'jwt',
                'provider' => null,
            ], config('auth.guards.jwt', [])),
        ]);

        if (!app()->configurationIsCached()) {
            $this->mergeConfigFrom(__DIR__ . '/../config/jwt.php', 'jwt');
        }

        app()->singleton('jwt', JWT::class);

        Auth::resolved(function ($auth) {
            $auth->extend('jwt', function ($app, $name, array $config) use ($auth) {
                return tap($this->createGuard($auth, $config), function ($guard) {
                    app()->refresh('request', $guard, 'setRequest');
                });
            });
        });
    }

    public function boot()
    {
        if (app()->runningInConsole()) {
            $this->commands([
                CreateSecretKeyCommand::class,
            ]);
            $this->publishes([
                __DIR__ . '/../migrations' => database_path('migrations'),
            ], 'jwt-migrations');
            $this->publishes([
                __DIR__ . '/../config/jwt.php' => config_path('jwt.php'),
            ], 'jwt-config');
        }
    }

    protected function createGuard($auth, $config)
    {
        return new RequestGuard(
            new Guard(),
            request(),
            $auth->createUserProvider($config['provider'] ?? null)
        );
    }
}
