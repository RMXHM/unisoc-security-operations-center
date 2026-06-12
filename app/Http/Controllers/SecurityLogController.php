<?php

namespace App\Http\Controllers;

use App\Models\BlockedIpR1;
use App\Models\BannedUserR1;
use App\Models\SecurityLog;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;

class SecurityLogController extends Controller
{
    private const ALLOWED_RISKS = ['low', 'medium', 'high', 'critical'];

    private const ALLOWED_STATUSES = ['success', 'failed', 'blocked', 'suspicious'];

    public function index(Request $request): JsonResponse
    {
        $validated = $request->validate([
            'page' => ['nullable', 'integer', 'min:1'],
            'per_page' => ['nullable', 'integer', 'min:1', 'max:250'],
            'search' => ['nullable', 'string', 'max:120'],
            'ip' => ['nullable', 'ip'],
            'user' => ['nullable', 'string', 'max:120'],
            'event' => ['nullable', 'string', 'max:120'],
            'risk' => ['nullable', 'string', Rule::in(self::ALLOWED_RISKS)],
            'status' => ['nullable', 'string', Rule::in(self::ALLOWED_STATUSES)],
        ]);

        $page = (int) ($validated['page'] ?? 1);
        $perPage = (int) ($validated['per_page'] ?? 25);
        $search = isset($validated['search']) ? trim($validated['search']) : null;

        $query = SecurityLog::query()->orderByDesc('timestamp')->orderByDesc('id');

        if ($search !== null && $search !== '') {
            $query->where(function ($builder) use ($search) {
                $builder
                    ->where('user', 'like', "%{$search}%")
                    ->orWhere('event', 'like', "%{$search}%")
                    ->orWhere('ip', 'like', "%{$search}%");
            });
        }

        if (!empty($validated['ip'])) {
            $query->where('ip', $validated['ip']);
        }

        if (!empty($validated['user'])) {
            $query->where('user', 'like', '%'.$validated['user'].'%');
        }

        if (!empty($validated['event'])) {
            $query->where('event', 'like', '%'.$validated['event'].'%');
        }

        if (!empty($validated['risk'])) {
            $query->where('risk', $validated['risk']);
        }

        if (!empty($validated['status'])) {
            $query->where('status', $validated['status']);
        }

        $paginator = $query->paginate($perPage, ['*'], 'page', $page);
        $activeBlockedIps = BlockedIpR1::query()->where('is_active', true)->pluck('ip');
        $activeBannedUsers = BannedUserR1::query()->where('is_active', true)->pluck('user_identifier');

        return response()->json([
            'data' => $paginator->getCollection()->map(fn (SecurityLog $log) => [
                'id' => $log->id,
                'user' => $log->user,
                'event' => $log->event,
                'ip' => $log->ip,
                'risk' => $log->risk,
                'status' => $log->status,
                'timestamp' => $log->timestamp?->toIso8601String(),
                'ip_blocked' => $activeBlockedIps->contains($log->ip),
                'user_banned' => $activeBannedUsers->contains($log->user),
            ])->values(),
            'meta' => [
                'page' => $paginator->currentPage(),
                'per_page' => $paginator->perPage(),
                'total' => $paginator->total(),
            ],
        ]);
    }
}
