<?php

namespace App\Services;

use App\Models\BlockedIpR1;
use App\Models\BannedUserR1;
use App\Models\SecurityLog;
use App\Models\SocActionAuditR1;
use Illuminate\Support\Carbon;
use Illuminate\Support\Collection;

class SocDashboardMetricsServiceR1
{
    public function buildSummary(): array
    {
        $logs = SecurityLog::query()
            ->orderByDesc('timestamp')
            ->orderByDesc('id')
            ->get();

        $activeBlockedIps = BlockedIpR1::query()
            ->where('is_active', true)
            ->pluck('ip');

        $activeBannedUsers = BannedUserR1::query()
            ->where('is_active', true)
            ->pluck('user_identifier');

        return [
            'metrics' => $this->buildMetrics($logs, $activeBlockedIps, $activeBannedUsers),
            'alerts' => $this->buildAlerts($logs),
            'timeline' => $this->buildTimeline($logs),
            'top_attackers' => $this->buildTopAttackers($logs, $activeBlockedIps),
            'anomalies' => $this->buildAnomalies($logs),
            'honeypot_hits' => $this->buildHoneypotHits($logs),
            'recent_actions' => $this->buildRecentActions(),
        ];
    }

    private function buildMetrics(Collection $logs, Collection $activeBlockedIps, Collection $activeBannedUsers): array
    {
        $now = Carbon::now();
        $lastHour = $logs->filter(fn (SecurityLog $log) => $log->timestamp && $log->timestamp->gte($now->copy()->subHour()));
        $lastDay = $logs->filter(fn (SecurityLog $log) => $log->timestamp && $log->timestamp->gte($now->copy()->subDay()));

        $threatEvents = $lastDay->filter(fn (SecurityLog $log) => $this->isThreatEvent($log));
        $activeThreats = $lastHour->filter(fn (SecurityLog $log) => $this->isThreatEvent($log))->count();
        $failedLogins = $lastHour->filter(fn (SecurityLog $log) => $this->isLoginEvent($log) && in_array($log->status, ['failed', 'blocked'], true))->count();
        $requestsPerMinute = max(1, (int) round($lastHour->count() / 60));

        $securityScore = 100;
        $securityScore -= min(30, $activeThreats * 4);
        $securityScore -= min(18, $activeBlockedIps->count() * 2);
        $securityScore -= min(12, $activeBannedUsers->count() * 3);
        $securityScore -= min(20, (int) floor($failedLogins / 2));
        $securityScore = max(28, $securityScore);

        return [
            'security_score' => $securityScore,
            'total_attacks' => $threatEvents->count(),
            'active_threats' => $activeThreats,
            'failed_logins' => $failedLogins,
            'requests_per_minute' => $requestsPerMinute,
            'blocked_ips' => $activeBlockedIps->count(),
            'banned_users' => $activeBannedUsers->count(),
        ];
    }

    private function buildAlerts(Collection $logs): array
    {
        $alerts = [];
        $now = Carbon::now();

        $bruteForceGroups = $logs
            ->filter(fn (SecurityLog $log) => $this->isLoginEvent($log)
                && in_array($log->status, ['failed', 'blocked'], true)
                && $log->timestamp
                && $log->timestamp->gte($now->copy()->subMinutes(15)))
            ->groupBy('ip');

        foreach ($bruteForceGroups as $ip => $group) {
            if ($group->count() >= 5) {
                $alerts[] = [
                    'id' => "brute-{$ip}",
                    'severity' => 'critical',
                    'message' => "Brute-force activity detected from {$ip} ({$group->count()} failed logins in 15 minutes)",
                    'created_at' => optional($group->sortByDesc('timestamp')->first()?->timestamp)->toIso8601String(),
                ];
            }
        }

        $recentCritical = $logs
            ->filter(fn (SecurityLog $log) => $log->risk === 'critical' && $log->timestamp && $log->timestamp->gte($now->copy()->subHour()))
            ->groupBy('ip')
            ->sortByDesc(fn (Collection $group) => $group->count());

        $topCritical = $recentCritical->first();
        if ($topCritical instanceof Collection && $topCritical->count() >= 3) {
            /** @var SecurityLog|null $sample */
            $sample = $topCritical->sortByDesc('timestamp')->first();
            if ($sample) {
                $alerts[] = [
                    'id' => "critical-{$sample->ip}",
                    'severity' => 'warning',
                    'message' => "High-risk IP cluster detected from {$sample->ip} ({$topCritical->count()} critical events in 60 minutes)",
                    'created_at' => optional($sample->timestamp)->toIso8601String(),
                ];
            }
        }

        $offHoursAdmin = $logs->first(fn (SecurityLog $log) => $this->isOffHoursAdminAccess($log));
        if ($offHoursAdmin) {
            $alerts[] = [
                'id' => "offhours-{$offHoursAdmin->id}",
                'severity' => 'warning',
                'message' => "Suspicious admin activity outside standard hours from {$offHoursAdmin->ip}",
                'created_at' => optional($offHoursAdmin->timestamp)->toIso8601String(),
            ];
        }

        $honeypotHit = $logs->first(fn (SecurityLog $log) => str_contains(strtoupper($log->event), 'HONEYPOT'));
        if ($honeypotHit) {
            $alerts[] = [
                'id' => "honeypot-{$honeypotHit->id}",
                'severity' => 'info',
                'message' => "Honeypot trap triggered by {$honeypotHit->ip} on {$honeypotHit->event}",
                'created_at' => optional($honeypotHit->timestamp)->toIso8601String(),
            ];
        }

        return collect($alerts)
            ->sortByDesc('created_at')
            ->take(6)
            ->values()
            ->all();
    }

    private function buildTopAttackers(Collection $logs, Collection $activeBlockedIps): array
    {
        return $logs
            ->filter(fn (SecurityLog $log) => $this->isThreatEvent($log))
            ->groupBy('ip')
            ->map(function (Collection $group, string $ip) use ($activeBlockedIps) {
                /** @var SecurityLog $latest */
                $latest = $group->sortByDesc('timestamp')->first();

                return [
                    'ip' => $ip,
                    'count' => $group->count(),
                    'blocked' => $activeBlockedIps->contains($ip),
                    'latest_event' => $latest->event,
                    'latest_risk' => $latest->risk,
                    'latest_status' => $latest->status,
                    'last_seen' => optional($latest->timestamp)->toIso8601String(),
                ];
            })
            ->sortByDesc('count')
            ->take(6)
            ->values()
            ->all();
    }

    private function buildTimeline(Collection $logs): array
    {
        $labels = [];
        $sql = [];
        $xss = [];
        $brute = [];
        $recon = [];
        $bucketCount = 12;
        $bucketMinutes = 5;
        $now = Carbon::now();

        for ($offset = $bucketCount - 1; $offset >= 0; $offset--) {
            $bucketEnd = $now->copy()->subMinutes($offset * $bucketMinutes);
            $bucketStart = $bucketEnd->copy()->subMinutes($bucketMinutes);
            $labels[] = $bucketEnd->format('H:i');

            $window = $logs->filter(fn (SecurityLog $log) => $log->timestamp
                && $log->timestamp->gt($bucketStart)
                && $log->timestamp->lte($bucketEnd));

            $sql[] = $window->filter(fn (SecurityLog $log) => str_contains(strtoupper($log->event), 'SQL'))->count();
            $xss[] = $window->filter(fn (SecurityLog $log) => str_contains(strtoupper($log->event), 'XSS'))->count();
            $brute[] = $window->filter(fn (SecurityLog $log) => str_contains(strtoupper($log->event), 'BRUTE')
                || ($this->isLoginEvent($log) && in_array($log->status, ['failed', 'blocked'], true)))->count();
            $recon[] = $window->filter(fn (SecurityLog $log) => str_contains(strtoupper($log->event), 'SCAN')
                || str_contains(strtoupper($log->event), 'PORT')
                || str_contains(strtoupper($log->event), 'HONEYPOT')
                || str_contains(strtoupper($log->event), 'DNS_TUNNEL'))->count();
        }

        return [
            'labels' => $labels,
            'sql' => $sql,
            'xss' => $xss,
            'brute' => $brute,
            'recon' => $recon,
        ];
    }

    private function buildAnomalies(Collection $logs): array
    {
        $anomalies = [];

        $bruteForce = $logs
            ->filter(fn (SecurityLog $log) => $this->isLoginEvent($log) && in_array($log->status, ['failed', 'blocked'], true))
            ->groupBy('ip')
            ->filter(fn (Collection $group) => $group->count() >= 5)
            ->sortByDesc(fn (Collection $group) => $group->count());

        foreach ($bruteForce->take(2) as $ip => $group) {
            $anomalies[] = [
                'user' => 'multiple identities',
                'label' => 'BLOCKED',
                'score' => 97,
                'trigger' => "{$group->count()} failed logins from {$ip}",
                'action' => 'Investigate',
            ];
        }

        foreach ($logs->filter(fn (SecurityLog $log) => $this->isOffHoursAdminAccess($log))->take(2) as $log) {
            $anomalies[] = [
                'user' => $log->user,
                'label' => 'FLAGGED',
                'score' => 78,
                'trigger' => "Off-hours admin activity from {$log->ip}",
                'action' => 'Review',
            ];
        }

        foreach ($logs->filter(fn (SecurityLog $log) => $log->status === 'suspicious')->take(2) as $log) {
            $anomalies[] = [
                'user' => $log->user,
                'label' => 'FLAGGED',
                'score' => 84,
                'trigger' => "{$log->event} classified as suspicious from {$log->ip}",
                'action' => 'Escalate',
            ];
        }

        if ($anomalies === []) {
            $anomalies[] = [
                'user' => 'baseline',
                'label' => 'NORMAL',
                'score' => 12,
                'trigger' => 'No anomalies detected in the active telemetry window',
                'action' => 'Monitor',
            ];
        }

        return array_slice($anomalies, 0, 6);
    }

    private function buildHoneypotHits(Collection $logs): array
    {
        return $logs
            ->filter(fn (SecurityLog $log) => str_contains(strtoupper($log->event), 'HONEYPOT'))
            ->take(8)
            ->map(fn (SecurityLog $log) => [
                'ip' => $log->ip,
                'event' => $log->event,
                'status' => $log->status,
                'timestamp' => optional($log->timestamp)->toIso8601String(),
            ])
            ->values()
            ->all();
    }

    private function buildRecentActions(): array
    {
        return SocActionAuditR1::query()
            ->latest()
            ->take(8)
            ->get()
            ->map(fn (SocActionAuditR1 $audit) => [
                'action' => $audit->action,
                'target_type' => $audit->target_type,
                'target_value' => $audit->target_value,
                'actor_email' => $audit->actor_email,
                'created_at' => optional($audit->created_at)->toIso8601String(),
            ])
            ->values()
            ->all();
    }

    private function isThreatEvent(SecurityLog $log): bool
    {
        return in_array($log->status, ['blocked', 'suspicious'], true)
            || in_array($log->risk, ['high', 'critical'], true);
    }

    private function isLoginEvent(SecurityLog $log): bool
    {
        return str_contains(strtoupper($log->event), 'LOGIN');
    }

    private function isOffHoursAdminAccess(SecurityLog $log): bool
    {
        if (!$log->timestamp) {
            return false;
        }

        $hour = (int) $log->timestamp->format('G');

        return str_contains(strtolower($log->user), 'admin')
            && ($hour < 5 || $hour >= 22)
            && (
                $this->isLoginEvent($log)
                || str_contains(strtoupper($log->event), 'CONFIG')
                || str_contains(strtoupper($log->event), 'EXPORT')
            );
    }
}
