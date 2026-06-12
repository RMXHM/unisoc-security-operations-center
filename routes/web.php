<?php

use App\Http\Middleware\EnsureSocAdminR1;
use App\Http\Middleware\SocApiSecurityHeaders;
use Illuminate\Support\Facades\Route;

$serveRootFile = static function (string $path, array $headers = []) {
    abort_unless(is_file($path), 404);

    return response()->file($path, $headers);
};

Route::middleware(SocApiSecurityHeaders::class)->group(function () use ($serveRootFile) {
    Route::get('/login', function () use ($serveRootFile) {
        if (auth()->check()) {
            return redirect('/');
        }

        return $serveRootFile(
            base_path('loginR1.html'),
            ['Content-Type' => 'text/html; charset=UTF-8']
        );
    });

    Route::middleware(EnsureSocAdminR1::class)->get('/', fn () => $serveRootFile(
        base_path('index.html'),
        ['Content-Type' => 'text/html; charset=UTF-8']
    ));

    Route::get('/style.css', fn () => $serveRootFile(
        base_path('style.css'),
        ['Content-Type' => 'text/css; charset=UTF-8']
    ));

    Route::get('/script.js', fn () => $serveRootFile(
        base_path('script.js'),
        ['Content-Type' => 'application/javascript; charset=UTF-8']
    ));

    Route::get('/authR1.js', fn () => $serveRootFile(
        base_path('authR1.js'),
        ['Content-Type' => 'application/javascript; charset=UTF-8']
    ));

    Route::get('/chartR1.js', fn () => $serveRootFile(
        base_path('chartR1.js'),
        ['Content-Type' => 'application/javascript; charset=UTF-8']
    ));

    Route::get('/logo.png', fn () => $serveRootFile(
        base_path('logo.png'),
        ['Content-Type' => 'image/png']
    ));
});
