<?php

namespace Database\Seeders;

use App\Models\SecurityLog;
use Illuminate\Database\Seeder;
use Illuminate\Support\Carbon;

class SecurityLogSeeder extends Seeder
{
    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        if (SecurityLog::query()->exists()) {
            return;
        }

        $now = Carbon::now();

        $rows = [
            ['mins' => 1, 'user' => 'unknown', 'event' => 'HONEYPOT_HIT', 'ip' => '45.33.12.99', 'risk' => 'critical', 'status' => 'blocked'],
            ['mins' => 3, 'user' => 'admin@university.edu', 'event' => 'CONFIG_CHANGE', 'ip' => '192.168.10.14', 'risk' => 'medium', 'status' => 'success'],
            ['mins' => 4, 'user' => 'admin@university.edu', 'event' => 'EXPORT_LOGS', 'ip' => '192.168.10.14', 'risk' => 'medium', 'status' => 'success'],
            ['mins' => 5, 'user' => 'unknown', 'event' => 'BRUTE_FORCE_LOGIN', 'ip' => '203.45.67.89', 'risk' => 'critical', 'status' => 'blocked'],
            ['mins' => 6, 'user' => 'unknown', 'event' => 'SQLI_PROBE', 'ip' => '203.45.67.89', 'risk' => 'critical', 'status' => 'blocked'],
            ['mins' => 8, 'user' => 'research-vpn', 'event' => 'LOGIN_FAILURE', 'ip' => '185.220.101.1', 'risk' => 'high', 'status' => 'failed'],
            ['mins' => 11, 'user' => 'idm-service', 'event' => 'LOGIN_SUCCESS', 'ip' => '10.20.1.11', 'risk' => 'low', 'status' => 'success'],
            ['mins' => 13, 'user' => 'unknown', 'event' => 'PORT_SCAN', 'ip' => '91.108.4.55', 'risk' => 'high', 'status' => 'blocked'],
            ['mins' => 16, 'user' => 'admin@university.edu', 'event' => 'LOGIN_SUCCESS', 'ip' => '192.168.10.14', 'risk' => 'low', 'status' => 'success'],
            ['mins' => 18, 'user' => 'unknown', 'event' => 'XSS_PROBE', 'ip' => '203.0.113.7', 'risk' => 'critical', 'status' => 'blocked'],
            ['mins' => 20, 'user' => 'archive-worker', 'event' => 'JOB_EXECUTION', 'ip' => '10.20.1.25', 'risk' => 'low', 'status' => 'success'],
            ['mins' => 23, 'user' => 'unknown', 'event' => 'LOGIN_FAILURE', 'ip' => '203.45.67.89', 'risk' => 'high', 'status' => 'failed'],
            ['mins' => 24, 'user' => 'unknown', 'event' => 'LOGIN_FAILURE', 'ip' => '203.45.67.89', 'risk' => 'high', 'status' => 'failed'],
            ['mins' => 25, 'user' => 'unknown', 'event' => 'LOGIN_FAILURE', 'ip' => '203.45.67.89', 'risk' => 'high', 'status' => 'failed'],
            ['mins' => 26, 'user' => 'unknown', 'event' => 'LOGIN_FAILURE', 'ip' => '203.45.67.89', 'risk' => 'high', 'status' => 'failed'],
            ['mins' => 27, 'user' => 'unknown', 'event' => 'LOGIN_FAILURE', 'ip' => '203.45.67.89', 'risk' => 'high', 'status' => 'failed'],
            ['mins' => 31, 'user' => 'identity-admin', 'event' => 'PRIV_ESC_ATTEMPT', 'ip' => '198.51.100.17', 'risk' => 'critical', 'status' => 'suspicious'],
            ['mins' => 36, 'user' => 'mail-gateway', 'event' => 'LOGIN_SUCCESS', 'ip' => '10.20.2.15', 'risk' => 'low', 'status' => 'success'],
            ['mins' => 42, 'user' => 'unknown', 'event' => 'DNS_TUNNEL_ATTEMPT', 'ip' => '198.51.100.44', 'risk' => 'high', 'status' => 'blocked'],
            ['mins' => 48, 'user' => 'backup-node', 'event' => 'FILE_ACCESS', 'ip' => '10.20.3.40', 'risk' => 'low', 'status' => 'success'],
            ['mins' => 52, 'user' => 'admin@university.edu', 'event' => 'LOGIN_SUCCESS', 'ip' => '10.10.4.8', 'risk' => 'medium', 'status' => 'suspicious'],
            ['mins' => 58, 'user' => 'unknown', 'event' => 'COMMAND_INJECTION_PROBE', 'ip' => '5.188.206.4', 'risk' => 'critical', 'status' => 'blocked'],
            ['mins' => 64, 'user' => 'unknown', 'event' => 'HONEYPOT_HIT', 'ip' => '45.33.12.99', 'risk' => 'critical', 'status' => 'blocked'],
            ['mins' => 75, 'user' => 'soc-orchestrator', 'event' => 'POLICY_SYNC', 'ip' => '10.20.1.9', 'risk' => 'low', 'status' => 'success'],
            ['mins' => 85, 'user' => 'unknown', 'event' => 'PORT_SCAN', 'ip' => '91.108.4.55', 'risk' => 'high', 'status' => 'blocked'],
            ['mins' => 95, 'user' => 'admin@university.edu', 'event' => 'EXPORT_LOGS', 'ip' => '192.168.10.14', 'risk' => 'medium', 'status' => 'success'],
            ['mins' => 112, 'user' => 'faculty-vpn', 'event' => 'LOGIN_FAILURE', 'ip' => '185.220.101.1', 'risk' => 'high', 'status' => 'failed'],
            ['mins' => 128, 'user' => 'unknown', 'event' => 'XSS_PROBE', 'ip' => '203.0.113.7', 'risk' => 'critical', 'status' => 'blocked'],
            ['mins' => 144, 'user' => 'unknown', 'event' => 'SQLI_PROBE', 'ip' => '203.45.67.89', 'risk' => 'critical', 'status' => 'blocked'],
            ['mins' => 158, 'user' => 'api-gateway', 'event' => 'RATE_LIMIT_TRIGGER', 'ip' => '10.20.1.30', 'risk' => 'medium', 'status' => 'success'],
            ['mins' => 176, 'user' => 'idm-service', 'event' => 'LOGIN_SUCCESS', 'ip' => '10.20.1.11', 'risk' => 'low', 'status' => 'success'],
            ['mins' => 194, 'user' => 'unknown', 'event' => 'BRUTE_FORCE_LOGIN', 'ip' => '203.45.67.89', 'risk' => 'critical', 'status' => 'blocked'],
            ['mins' => 240, 'user' => 'unknown', 'event' => 'HONEYPOT_HIT', 'ip' => '45.33.12.99', 'risk' => 'critical', 'status' => 'blocked'],
        ];

        SecurityLog::query()->insert(array_map(function (array $row) use ($now) {
            return [
                'user' => $row['user'],
                'event' => $row['event'],
                'ip' => $row['ip'],
                'risk' => $row['risk'],
                'status' => $row['status'],
                'timestamp' => $now->copy()->subMinutes($row['mins']),
            ];
        }, $rows));
    }
}
