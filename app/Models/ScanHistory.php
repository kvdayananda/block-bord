<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ScanHistory extends Model
{
    use HasFactory;

    protected $table = 'scans';

    protected $fillable = [
        'content',
        'url_hash',
        'risk_score',
        'risk_level',
        'reasons',
        'category',
        'scam_intent',
        'user_id',
    ];

    protected $casts = [
        'risk_score' => 'float',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class, 'user_id');
    }
}
