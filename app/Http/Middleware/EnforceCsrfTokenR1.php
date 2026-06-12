<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class EnforceCsrfTokenR1
{
    public function handle(Request $request, Closure $next): Response
    {
        if (!in_array($request->method(), ['POST', 'PUT', 'PATCH', 'DELETE'], true)) {
            return $next($request);
        }

        $sessionToken = $request->session()->token();
        $headerToken = $request->header('X-CSRF-TOKEN');

        if (!$sessionToken || !$headerToken || !hash_equals($sessionToken, $headerToken)) {
            return new JsonResponse([
                'message' => 'CSRF token mismatch.',
            ], 419);
        }

        return $next($request);
    }
}
