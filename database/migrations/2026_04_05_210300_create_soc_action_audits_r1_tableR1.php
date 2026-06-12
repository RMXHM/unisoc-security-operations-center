<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('soc_action_audits_r1', function (Blueprint $table): void {
            $table->id();
            $table->string('action', 80)->index();
            $table->string('target_type', 40);
            $table->string('target_value', 160);
            $table->json('details')->nullable();
            $table->string('actor_email', 120);
            $table->string('ip_address', 45)->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('soc_action_audits_r1');
    }
};
