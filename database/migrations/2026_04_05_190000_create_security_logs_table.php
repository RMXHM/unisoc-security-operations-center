<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('security_logs', function (Blueprint $table) {
            $table->id();
            $table->string('user', 120);
            $table->string('event', 120);
            $table->string('ip', 45);
            $table->string('risk', 16);
            $table->string('status', 16);
            $table->dateTime('timestamp');

            $table->index('timestamp');
            $table->index('risk');
            $table->index('status');
            $table->index('ip');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('security_logs');
    }
};
