<?php

use App\Http\Controllers\AuthControllerR1;
use App\Http\Controllers\SecurityLogController;
use App\Http\Controllers\SocActionControllerR1;
use App\Http\Controllers\SocDashboardControllerR1;
use App\Http\Middleware\EnforceCsrfTokenR1;
use App\Http\Middleware\EnsureSocAdminR1;
use App\Http\Middleware\SocApiSecurityHeaders;
use Illuminate\Support\Facades\Route;

Route::middleware(['web', SocApiSecurityHeaders::class])->group(function () {
    Route::get('/session', [AuthControllerR1::class, 'session'])->middleware('throttle:soc-api');
    Route::post('/login', [AuthControllerR1::class, 'login'])->middleware([EnforceCsrfTokenR1::class, 'throttle:soc-auth']);

    Route::middleware(EnsureSocAdminR1::class)->group(function () {
        Route::post('/logout', [AuthControllerR1::class, 'logout'])->middleware([EnforceCsrfTokenR1::class, 'throttle:soc-actions']);
        Route::get('/logs', [SecurityLogController::class, 'index'])->middleware('throttle:soc-api');
        Route::get('/dashboard-summary', [SocDashboardControllerR1::class, 'summary'])->middleware('throttle:soc-api');
        Route::post('/block-ip', [SocActionControllerR1::class, 'blockIp'])->middleware([EnforceCsrfTokenR1::class, 'throttle:soc-actions']);
        Route::post('/unblock-ip', [SocActionControllerR1::class, 'unblockIp'])->middleware([EnforceCsrfTokenR1::class, 'throttle:soc-actions']);
        Route::post('/ban-user', [SocActionControllerR1::class, 'banUser'])->middleware([EnforceCsrfTokenR1::class, 'throttle:soc-actions']);
        Route::post('/mark-suspicious', [SocActionControllerR1::class, 'markSuspicious'])->middleware([EnforceCsrfTokenR1::class, 'throttle:soc-actions']);
        Route::delete('/log/{log}', [SocActionControllerR1::class, 'deleteLog'])->middleware([EnforceCsrfTokenR1::class, 'throttle:soc-actions']);
    });
});
