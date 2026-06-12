<?php

namespace App\Http\Controllers;

use App\Services\SocDashboardMetricsServiceR1;
use Illuminate\Http\JsonResponse;

class SocDashboardControllerR1 extends Controller
{
    public function __construct(private readonly SocDashboardMetricsServiceR1 $metricsService)
    {
    }

    public function summary(): JsonResponse
    {
        return response()->json($this->metricsService->buildSummary());
    }
}
