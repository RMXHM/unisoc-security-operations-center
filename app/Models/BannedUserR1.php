<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class BannedUserR1 extends Model
{
    protected $table = 'banned_users_r1';

    protected $fillable = [
        'user_identifier',
        'reason',
        'banned_by',
        'is_active',
        'banned_at',
    ];

    protected function casts(): array
    {
        return [
            'is_active' => 'boolean',
            'banned_at' => 'datetime',
        ];
    }
}
