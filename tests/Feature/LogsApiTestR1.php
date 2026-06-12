<?php

namespace Tests\Feature;

use App\Models\BlockedIpR1;
use App\Models\BannedUserR1;
use App\Models\SecurityLog;
use App\Services\SocAdminAccountServiceR1;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class LogsApiTestR1 extends TestCase
{
    use RefreshDatabase;

    public function test_logs_api_requires_an_authenticated_soc_session(): void
    {
        $this->getJson('/api/logs')
            ->assertStatus(401)
            ->assertJsonPath('message', 'Unauthenticated SOC session.');
    }

    public function test_logs_api_returns_expected_schema_and_derived_state(): void
    {
        $admin = app(SocAdminAccountServiceR1::class)->ensureAdminAccount();

        $older = SecurityLog::query()->create([
            'user' => 'soc-analyst',
            'event' => 'LOGIN_SUCCESS',
            'ip' => '192.168.10.14',
            'risk' => 'low',
            'status' => 'success',
            'timestamp' => now()->subMinutes(20),
        ]);

        $newer = SecurityLog::query()->create([
            'user' => 'unknown',
            'event' => 'SQLI_PROBE',
            'ip' => '203.45.67.89',
            'risk' => 'critical',
            'status' => 'blocked',
            'timestamp' => now()->subMinute(),
        ]);

        BlockedIpR1::query()->create([
            'ip' => '203.45.67.89',
            'blocked_by' => $admin->email,
            'is_active' => true,
            'blocked_at' => now(),
        ]);

        BannedUserR1::query()->create([
            'user_identifier' => 'unknown',
            'banned_by' => $admin->email,
            'is_active' => true,
            'banned_at' => now(),
        ]);

        $response = $this->actingAs($admin)->getJson('/api/logs');

        $response
            ->assertOk()
            ->assertJsonStructure([
                'data' => [
                    '*' => ['id', 'user', 'event', 'ip', 'risk', 'status', 'timestamp', 'ip_blocked', 'user_banned'],
                ],
                'meta' => ['page', 'per_page', 'total'],
            ])
            ->assertJsonPath('data.0.id', $newer->id)
            ->assertJsonPath('data.0.ip_blocked', true)
            ->assertJsonPath('data.0.user_banned', true)
            ->assertJsonPath('data.1.id', $older->id)
            ->assertJsonPath('meta.total', 2);
    }

    public function test_logs_api_supports_filters_and_pagination(): void
    {
        $admin = app(SocAdminAccountServiceR1::class)->ensureAdminAccount();

        SecurityLog::query()->create([
            'user' => 'admin@university.edu',
            'event' => 'EXPORT_LOGS',
            'ip' => '192.168.10.14',
            'risk' => 'medium',
            'status' => 'success',
            'timestamp' => now()->subMinutes(5),
        ]);

        SecurityLog::query()->create([
            'user' => 'unknown',
            'event' => 'PORT_SCAN',
            'ip' => '91.108.4.55',
            'risk' => 'high',
            'status' => 'blocked',
            'timestamp' => now()->subMinutes(4),
        ]);

        SecurityLog::query()->create([
            'user' => 'unknown',
            'event' => 'SQLI_PROBE',
            'ip' => '203.45.67.89',
            'risk' => 'critical',
            'status' => 'blocked',
            'timestamp' => now()->subMinutes(3),
        ]);

        $response = $this->actingAs($admin)
            ->getJson('/api/logs?status=blocked&user=unknown&per_page=1&page=2');

        $response
            ->assertOk()
            ->assertJsonPath('meta.page', 2)
            ->assertJsonPath('meta.per_page', 1)
            ->assertJsonPath('meta.total', 2)
            ->assertJsonCount(1, 'data');
    }

    public function test_logs_api_rejects_invalid_query_parameters(): void
    {
        $admin = app(SocAdminAccountServiceR1::class)->ensureAdminAccount();

        $this->actingAs($admin)
            ->getJson('/api/logs?risk=extreme&per_page=500')
            ->assertStatus(422)
            ->assertJsonValidationErrors(['risk', 'per_page']);
    }

    public function test_logs_api_applies_security_headers(): void
    {
        $admin = app(SocAdminAccountServiceR1::class)->ensureAdminAccount();

        SecurityLog::query()->create([
            'user' => 'soc-analyst',
            'event' => 'LOGIN_SUCCESS',
            'ip' => '192.168.10.14',
            'risk' => 'low',
            'status' => 'success',
            'timestamp' => now(),
        ]);

        $this->actingAs($admin)
            ->getJson('/api/logs')
            ->assertOk()
            ->assertHeader('X-Content-Type-Options', 'nosniff')
            ->assertHeader('X-Frame-Options', 'SAMEORIGIN')
            ->assertHeader('Content-Security-Policy');
    }
}
