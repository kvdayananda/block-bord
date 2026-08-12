<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Foundation\Auth\User as Authenticatable;
use Illuminate\Notifications\Notifiable;
use Illuminate\Database\Eloquent\Relations\HasMany;

class User extends Authenticatable
{
    use HasFactory, Notifiable;

    protected $fillable = [
        'username',
        'email',
        'password',
        'is_active',
        'is_email_verified',
        'is_pro',
        'is_admin',
        'plan',
        'api_key',
        'totp_secret',
        'totp_enabled',
    ];

    protected $hidden = [
        'password',
        'remember_token',
        'totp_secret',
    ];

    protected function casts(): array
    {
        return [
            'is_active' => 'boolean',
            'is_email_verified' => 'boolean',
            'is_pro' => 'boolean',
            'is_admin' => 'boolean',
            'totp_enabled' => 'boolean',
            'password' => 'hashed',
        ];
    }

    public function scans(): HasMany
    {
        return $this->hasMany(ScanHistory::class, 'user_id');
    }

    public function payments(): HasMany
    {
        return $this->hasMany(Payment::class, 'user_id');
    }

    public function reports(): HasMany
    {
        return $this->hasMany(UserReport::class, 'user_id');
    }

    public function tickets(): HasMany
    {
        return $this->hasMany(SupportTicket::class, 'user_id');
    }

    public function bulkScans(): HasMany
    {
        return $this->hasMany(BulkScanJob::class, 'user_id');
    }
}
