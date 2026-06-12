<?php

namespace App\Http\Controllers;

use App\Services\SocAdminAccountServiceR1;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthControllerR1 extends Controller
{
    public function __construct(private readonly SocAdminAccountServiceR1 $adminAccountService)
    {
    }

    public function session(Request $request): JsonResponse
    {
        $this->adminAccountService->ensureAdminAccount();
        $user = $request->user();

        return response()->json([
            'authenticated' => $this->adminAccountService->isAdmin($user),
            'user' => $this->adminAccountService->isAdmin($user) ? [
                'name' => $user->name,
                'email' => $user->email,
            ] : null,
            'csrfToken' => csrf_token(),
        ]);
    }

    public function login(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'email' => ['required', 'email', 'max:120'],
            'password' => ['required', 'string', 'min:10', 'max:120'],
        ]);

        $admin = $this->adminAccountService->ensureAdminAccount();

        if (strcasecmp($validated['email'], $admin->email) !== 0 || !Hash::check($validated['password'], $admin->password)) {
            return response()->json([
                'message' => 'Invalid SOC administrator credentials.',
            ], 422);
        }

        Auth::guard('web')->login($admin, false);
        $request->session()->regenerate();

        return response()->json([
            'message' => 'SOC administrator authenticated.',
            'user' => [
                'name' => $admin->name,
                'email' => $admin->email,
            ],
            'csrfToken' => csrf_token(),
        ]);
    }

    public function logout(Request $request): JsonResponse
    {
        Auth::guard('web')->logout();

        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return response()->json([
            'message' => 'SOC session closed.',
            'csrfToken' => csrf_token(),
        ]);
    }
}
