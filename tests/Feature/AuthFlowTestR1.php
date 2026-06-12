<?php

namespace Tests\Feature;

use App\Services\SocAdminAccountServiceR1;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class AuthFlowTestR1 extends TestCase
{
    use RefreshDatabase;

    public function test_session_endpoint_bootstraps_guest_state_and_csrf_token(): void
    {
        $response = $this->getJson('/api/session');

        $response
            ->assertOk()
            ->assertJsonPath('authenticated', false)
            ->assertJsonStructure(['authenticated', 'user', 'csrfToken']);
    }

    public function test_login_endpoint_authenticates_admin_session(): void
    {
        $adminService = app(SocAdminAccountServiceR1::class);
        $csrfToken = $this->getJson('/api/session')->json('csrfToken');

        $response = $this
            ->withHeader('X-CSRF-TOKEN', $csrfToken)
            ->postJson('/api/login', [
                'email' => $adminService->adminEmail(),
                'password' => $adminService->adminPassword(),
            ]);

        $response
            ->assertOk()
            ->assertJsonPath('user.email', $adminService->adminEmail())
            ->assertJsonStructure(['message', 'user', 'csrfToken']);

        $this->getJson('/api/session')
            ->assertOk()
            ->assertJsonPath('authenticated', true)
            ->assertJsonPath('user.email', $adminService->adminEmail());
    }

    public function test_login_endpoint_rejects_invalid_credentials(): void
    {
        $csrfToken = $this->getJson('/api/session')->json('csrfToken');

        $this->withHeader('X-CSRF-TOKEN', $csrfToken)
            ->postJson('/api/login', [
                'email' => 'admin@university.edu',
                'password' => 'wrong-password',
            ])
            ->assertStatus(422)
            ->assertJsonPath('message', 'Invalid SOC administrator credentials.');
    }

    public function test_logout_endpoint_invalidates_the_session(): void
    {
        $adminService = app(SocAdminAccountServiceR1::class);
        $admin = $adminService->ensureAdminAccount();
        $csrfToken = 'logout-token';

        $this->actingAs($admin)
            ->withSession(['_token' => $csrfToken])
            ->withHeader('X-CSRF-TOKEN', $csrfToken)
            ->postJson('/api/logout')
            ->assertOk()
            ->assertJsonPath('message', 'SOC session closed.');

        $this->postJson('/api/logout')
            ->assertStatus(401);
    }
}
