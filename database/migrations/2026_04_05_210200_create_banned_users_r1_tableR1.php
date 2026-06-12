<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('banned_users_r1', function (Blueprint $table): void {
            $table->id();
            $table->string('user_identifier', 120)->unique();
            $table->string('reason', 180)->nullable();
            $table->string('banned_by', 120);
            $table->boolean('is_active')->default(true)->index();
            $table->timestamp('banned_at')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('banned_users_r1');
    }
};
