<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class SecurityLog extends Model
{
    use SoftDeletes;

    public $timestamps = false;

    protected $fillable = [
        'user',
        'event',
        'ip',
        'risk',
        'status',
        'timestamp',
    ];

    protected function casts(): array
    {
        return [
            'timestamp' => 'datetime',
            'deleted_at' => 'datetime',
        ];
    }
}
