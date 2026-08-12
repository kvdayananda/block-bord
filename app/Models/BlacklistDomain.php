<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class BlacklistDomain extends Model
{
    use HasFactory;

    protected $table = 'blacklist_domains';

    protected $fillable = [
        'domain',
        'added_by_user_id',
        'reason',
    ];

    public function addedBy(): BelongsTo
    {
        return $this->belongsTo(User::class, 'added_by_user_id');
    }
}
