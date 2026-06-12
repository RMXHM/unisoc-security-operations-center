<?php

namespace App\Providers;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\RateLimiter;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        RateLimiter::for('soc-api', function (Request $request) {
            return Limit::perMinute(60)->by($request->ip() ?: 'soc-api');
        });

        RateLimiter::for('soc-auth', function (Request $request) {
            $key = implode('|', [
                strtolower((string) $request->input('email', 'guest')),
                $request->ip() ?: 'soc-auth',
            ]);

            return Limit::perMinute(10)->by($key);
        });

        RateLimiter::for('soc-actions', function (Request $request) {
            $actor = $request->user()?->email ?? 'guest';

            return Limit::perMinute(90)->by($actor.'|'.($request->ip() ?: 'soc-actions'));
        });
    }
}
