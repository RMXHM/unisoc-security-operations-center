<?php

namespace Tests\Feature;

use App\Models\BlockedIpR1;
use App\Models\BannedUserR1;
use App\Models\SecurityLog;
use App\Models\SocActionAuditR1;
use App\Services\SocAdminAccountServiceR1;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class SocActionApiTestR1 extends TestCase
{
    use RefreshDatabase;

    private function authenticateAdminWithCsrf(): array
    {
        $admin = app(SocAdminAccountServiceR1::class)->ensureAdminAccount();
        $csrfToken = 'soc-test-token';

        return [$admin, $csrfToken];
    }

    public function test_block_and_unblock_ip_actions_persist_and_audit(): void
    {
        [$admin, $csrfToken] = $this->authenticateAdminWithCsrf();

        $log = SecurityLog::query()->create([
            'user' => 'unknown',
            'event' => 'PORT_SCAN',
            'ip' => '203.45.67.89',
            'risk' => 'high',
            'status' => 'failed',
            'timestamp' => now(),
        ]);

        $this->actingAs($admin)
            ->withSession(['_token' => $csrfToken])
            ->withHeader('X-CSRF-TOKEN', $csrfToken)
            ->postJson('/api/block-ip', [
                'ip' => $log->ip,
                'log_id' => $log->id,
            ])
            ->assertOk()
            ->assertJsonPath('target.blocked', true);

        $this->assertDatabaseHas('blocked_ips_r1', [
            'ip' => $log->ip,
            'is_active' => true,
        ]);

        $this->assertDatabaseHas('soc_action_audits_r1', [
            'action' => 'BLOCK_IP',
            'target_value' => $log->ip,
        ]);

        $this->actingAs($admin)
            ->withSession(['_token' => $csrfToken])
            ->withHeader('X-CSRF-TOKEN', $csrfToken)
            ->postJson('/api/unblock-ip', [
                'ip' => $log->ip,
            ])
            ->assertOk()
            ->assertJsonPath('target.blocked', false);

        $this->assertDatabaseHas('blocked_ips_r1', [
            'ip' => $log->ip,
            'is_active' => false,
        ]);
    }

    public function test_ban_mark_suspicious_and_delete_actions_update_records(): void
    {
        [$admin, $csrfToken] = $this->authenticateAdminWithCsrf();

        $banLog = SecurityLog::query()->create([
            'user' => 'student.target',
            'event' => 'LOGIN_FAILURE',
            'ip' => '198.51.100.77',
            'risk' => 'medium',
            'status' => 'failed',
            'timestamp' => now(),
        ]);

        $suspiciousLog = SecurityLog::query()->create([
            'user' => 'operator',
            'event' => 'EXPORT_LOGS',
            'ip' => '192.168.10.14',
            'risk' => 'low',
            'status' => 'success',
            'timestamp' => now(),
        ]);

        $deleteLog = SecurityLog::query()->create([
            'user' => 'unknown',
            'event' => 'SQLI_PROBE',
            'ip' => '203.0.113.9',
            'risk' => 'critical',
            'status' => 'blocked',
            'timestamp' => now(),
        ]);

        $this->actingAs($admin)
            ->withSession(['_token' => $csrfToken])
            ->withHeader('X-CSRF-TOKEN', $csrfToken)
            ->postJson('/api/ban-user', [
                'user' => $banLog->user,
                'log_id' => $banLog->id,
            ])
            ->assertOk()
            ->assertJsonPath('target.banned', true);

        $this->assertDatabaseHas('banned_users_r1', [
            'user_identifier' => $banLog->user,
            'is_active' => true,
        ]);

        $this->actingAs($admin)
            ->withSession(['_token' => $csrfToken])
            ->withHeader('X-CSRF-TOKEN', $csrfToken)
            ->postJson('/api/mark-suspicious', [
                'log_id' => $suspiciousLog->id,
            ])
            ->assertOk()
            ->assertJsonPath('log.status', 'suspicious');

        $this->assertDatabaseHas('security_logs', [
            'id' => $suspiciousLog->id,
            'status' => 'suspicious',
        ]);

        $this->actingAs($admin)
            ->withSession(['_token' => $csrfToken])
            ->withHeader('X-CSRF-TOKEN', $csrfToken)
            ->deleteJson("/api/log/{$deleteLog->id}")
            ->assertOk()
            ->assertJsonPath('deleted_id', $deleteLog->id);

        $this->assertSoftDeleted('security_logs', [
            'id' => $deleteLog->id,
        ]);

        $this->assertTrue(SocActionAuditR1::query()->count() >= 3);
    }

    public function test_mutating_actions_require_csrf_token(): void
    {
        [$admin] = $this->authenticateAdminWithCsrf();

        $this->actingAs($admin)
            ->postJson('/api/block-ip', [
                'ip' => '203.45.67.89',
            ])
            ->assertStatus(419);
    }

    public function test_summary_endpoint_reflects_persisted_security_state(): void
    {
        [$admin, $csrfToken] = $this->authenticateAdminWithCsrf();

        SecurityLog::query()->create([
            'user' => 'unknown',
            'event' => 'BRUTE_FORCE_LOGIN',
            'ip' => '203.45.67.89',
            'risk' => 'critical',
            'status' => 'blocked',
            'timestamp' => now(),
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

        $this->actingAs($admin)
            ->withSession(['_token' => $csrfToken])
            ->getJson('/api/dashboard-summary')
            ->assertOk()
            ->assertJsonStructure(['metrics', 'alerts', 'timeline', 'top_attackers', 'anomalies', 'honeypot_hits', 'recent_actions'])
            ->assertJsonPath('metrics.blocked_ips', 1)
            ->assertJsonPath('metrics.banned_users', 1);
    }
}
