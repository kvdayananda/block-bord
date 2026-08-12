<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class BulkScanJob extends Model
{
    use HasFactory;

    protected $table = 'bulk_scan_jobs';

    protected $fillable = [
        'user_id',
        'status',
        'total_urls',
        'completed_urls',
        'results_json',
        'completed_at',
    ];

    protected $casts = [
        'completed_at' => 'datetime',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class, 'user_id');
    }
}
