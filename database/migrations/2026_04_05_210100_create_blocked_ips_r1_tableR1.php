<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('blocked_ips_r1', function (Blueprint $table): void {
            $table->id();
            $table->string('ip', 45)->unique();
            $table->string('reason', 180)->nullable();
            $table->string('blocked_by', 120);
            $table->boolean('is_active')->default(true)->index();
            $table->timestamp('blocked_at')->nullable();
            $table->timestamp('unblocked_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('blocked_ips_r1');
    }
};
