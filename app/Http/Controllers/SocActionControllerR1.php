<?php

namespace App\Http\Controllers;

use App\Models\BlockedIpR1;
use App\Models\BannedUserR1;
use App\Models\SecurityLog;
use App\Models\SocActionAuditR1;
use App\Services\SocDashboardMetricsServiceR1;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\Rule;

class SocActionControllerR1 extends Controller
{
    public function __construct(private readonly SocDashboardMetricsServiceR1 $metricsService)
    {
    }

    public function blockIp(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'ip' => ['required', 'ip'],
            'reason' => ['nullable', 'string', 'max:180'],
            'log_id' => ['nullable', 'integer', Rule::exists('security_logs', 'id')],
        ]);

        $log = null;

        DB::transaction(function () use ($request, $validated, &$log): void {
            BlockedIpR1::query()->updateOrCreate(
                ['ip' => $validated['ip']],
                [
                    'reason' => trim((string) ($validated['reason'] ?? 'Blocked by SOC operator')),
                    'blocked_by' => $request->user()->email,
                    'is_active' => true,
                    'blocked_at' => now(),
                    'unblocked_at' => null,
                ]
            );

            $log = $this->resolveLog($validated['log_id'] ?? null);
            if ($log) {
                $log->status = 'blocked';
                $log->save();
            }

            $this->audit($request, 'BLOCK_IP', 'ip', $validated['ip'], [
                'log_id' => $log?->id,
                'reason' => $validated['reason'] ?? null,
            ]);
        });

        return response()->json([
            'message' => "IP {$validated['ip']} blocked.",
            'target' => [
                'ip' => $validated['ip'],
                'blocked' => true,
            ],
            'log' => $log ? $this->transformLog($log) : null,
            'summary' => $this->metricsService->buildSummary(),
        ]);
    }

    public function unblockIp(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'ip' => ['required', 'ip'],
            'reason' => ['nullable', 'string', 'max:180'],
        ]);

        DB::transaction(function () use ($request, $validated): void {
            BlockedIpR1::query()
                ->where('ip', $validated['ip'])
                ->update([
                    'is_active' => false,
                    'unblocked_at' => now(),
                    'reason' => trim((string) ($validated['reason'] ?? 'Unblocked by SOC operator')),
                    'blocked_by' => $request->user()->email,
                ]);

            $this->audit($request, 'UNBLOCK_IP', 'ip', $validated['ip'], [
                'reason' => $validated['reason'] ?? null,
            ]);
        });

        return response()->json([
            'message' => "IP {$validated['ip']} unblocked.",
            'target' => [
                'ip' => $validated['ip'],
                'blocked' => false,
            ],
            'summary' => $this->metricsService->buildSummary(),
        ]);
    }

    public function banUser(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'user' => ['required', 'string', 'min:2', 'max:120'],
            'reason' => ['nullable', 'string', 'max:180'],
            'log_id' => ['nullable', 'integer', Rule::exists('security_logs', 'id')],
        ]);

        $normalizedUser = trim($validated['user']);
        $log = null;

        DB::transaction(function () use ($request, $normalizedUser, $validated, &$log): void {
            BannedUserR1::query()->updateOrCreate(
                ['user_identifier' => $normalizedUser],
                [
                    'reason' => trim((string) ($validated['reason'] ?? 'Banned by SOC operator')),
                    'banned_by' => $request->user()->email,
                    'is_active' => true,
                    'banned_at' => now(),
                ]
            );

            $log = $this->resolveLog($validated['log_id'] ?? null);
            if ($log) {
                $log->status = 'blocked';
                $log->save();
            }

            $this->audit($request, 'BAN_USER', 'user', $normalizedUser, [
                'log_id' => $log?->id,
                'reason' => $validated['reason'] ?? null,
            ]);
        });

        return response()->json([
            'message' => "User {$normalizedUser} banned.",
            'target' => [
                'user' => $normalizedUser,
                'banned' => true,
            ],
            'log' => $log ? $this->transformLog($log) : null,
            'summary' => $this->metricsService->buildSummary(),
        ]);
    }

    public function markSuspicious(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'log_id' => ['required', 'integer', Rule::exists('security_logs', 'id')],
            'reason' => ['nullable', 'string', 'max:180'],
        ]);

        /** @var SecurityLog $log */
        $log = SecurityLog::query()->findOrFail($validated['log_id']);

        DB::transaction(function () use ($request, $validated, $log): void {
            $log->status = 'suspicious';
            if ($log->risk === 'low') {
                $log->risk = 'medium';
            }
            $log->save();

            $this->audit($request, 'MARK_SUSPICIOUS', 'log', (string) $log->id, [
                'reason' => $validated['reason'] ?? null,
                'ip' => $log->ip,
                'user' => $log->user,
            ]);
        });

        return response()->json([
            'message' => "Log {$log->id} marked suspicious.",
            'log' => $this->transformLog($log->fresh()),
            'summary' => $this->metricsService->buildSummary(),
        ]);
    }

    public function deleteLog(Request $request, SecurityLog $log): JsonResponse
    {
        DB::transaction(function () use ($request, $log): void {
            $this->audit($request, 'DELETE_LOG', 'log', (string) $log->id, [
                'ip' => $log->ip,
                'user' => $log->user,
                'event' => $log->event,
            ]);

            $log->delete();
        });

        return response()->json([
            'message' => "Log {$log->id} deleted from active view.",
            'deleted_id' => $log->id,
            'summary' => $this->metricsService->buildSummary(),
        ]);
    }

    private function resolveLog(?int $logId): ?SecurityLog
    {
        if (!$logId) {
            return null;
        }

        return SecurityLog::query()->find($logId);
    }

    private function audit(Request $request, string $action, string $targetType, string $targetValue, array $details = []): void
    {
        SocActionAuditR1::query()->create([
            'action' => $action,
            'target_type' => $targetType,
            'target_value' => $targetValue,
            'details' => $details,
            'actor_email' => $request->user()->email,
            'ip_address' => $request->ip(),
        ]);
    }

    private function transformLog(SecurityLog $log): array
    {
        $ipBlocked = BlockedIpR1::query()->where('ip', $log->ip)->where('is_active', true)->exists();
        $userBanned = BannedUserR1::query()->where('user_identifier', $log->user)->where('is_active', true)->exists();

        return [
            'id' => $log->id,
            'user' => $log->user,
            'event' => $log->event,
            'ip' => $log->ip,
            'risk' => $log->risk,
            'status' => $log->status,
            'timestamp' => $log->timestamp?->toIso8601String(),
            'ip_blocked' => $ipBlocked,
            'user_banned' => $userBanned,
        ];
    }
}
