<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('security_logs', function (Blueprint $table): void {
            if (!Schema::hasColumn('security_logs', 'deleted_at')) {
                $table->softDeletes()->after('timestamp');
            }
        });
    }

    public function down(): void
    {
        Schema::table('security_logs', function (Blueprint $table): void {
            if (Schema::hasColumn('security_logs', 'deleted_at')) {
                $table->dropSoftDeletes();
            }
        });
    }
};
