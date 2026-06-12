<?php

namespace App\Services;

use App\Models\User;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Support\Facades\Hash;
use RuntimeException;

class SocAdminAccountServiceR1
{
    public function ensureAdminAccount(): User
    {
        $user = User::query()->firstOrNew(['email' => $this->adminEmail()]);
        $user->name = $this->adminName();
        $user->password = Hash::make($this->adminPassword());

        $user->save();

        return $user;
    }

    public function isAdmin(?Authenticatable $user): bool
    {
        if (!$user instanceof User) {
            return false;
        }

        return strcasecmp($user->email, $this->adminEmail()) === 0;
    }

    public function adminName(): string
    {
        return $this->requiredEnv('SOC_ADMIN_NAME');
    }

    public function adminEmail(): string
    {
        return $this->requiredEnv('SOC_ADMIN_EMAIL');
    }

    public function adminPassword(): string
    {
        return $this->requiredEnv('SOC_ADMIN_PASSWORD');
    }

    private function requiredEnv(string $key): string
    {
        $value = env($key);

        if (!is_string($value) || trim($value) === '') {
            throw new RuntimeException("Missing required environment variable: {$key}");
        }

        return $value;
    }
}
