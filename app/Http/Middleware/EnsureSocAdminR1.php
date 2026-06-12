<?php

namespace App\Http\Middleware;

use App\Services\SocAdminAccountServiceR1;
use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EnsureSocAdminR1
{
    public function __construct(private readonly SocAdminAccountServiceR1 $adminAccountService)
    {
    }

    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        if (!$this->adminAccountService->isAdmin($user)) {
            if ($request->expectsJson() || $request->is('api/*')) {
                return new JsonResponse([
                    'message' => 'Unauthenticated SOC session.',
                ], 401);
            }

            return redirect('/login');
        }

        return $next($request);
    }
}
