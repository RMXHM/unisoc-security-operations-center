<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class BlockedIpR1 extends Model
{
    protected $table = 'blocked_ips_r1';

    protected $fillable = [
        'ip',
        'reason',
        'blocked_by',
        'is_active',
        'blocked_at',
        'unblocked_at',
    ];

    protected function casts(): array
    {
        return [
            'is_active' => 'boolean',
            'blocked_at' => 'datetime',
            'unblocked_at' => 'datetime',
        ];
    }
}
