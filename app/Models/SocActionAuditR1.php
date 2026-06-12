<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class SocActionAuditR1 extends Model
{
    protected $table = 'soc_action_audits_r1';

    protected $fillable = [
        'action',
        'target_type',
        'target_value',
        'details',
        'actor_email',
        'ip_address',
    ];

    protected function casts(): array
    {
        return [
            'details' => 'array',
            'created_at' => 'datetime',
            'updated_at' => 'datetime',
        ];
    }
}
