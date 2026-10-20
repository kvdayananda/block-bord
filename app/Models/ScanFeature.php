<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ScanFeature extends Model
{
    use HasFactory;

    protected $guarded = [];

    protected $casts = ['features_json' => 'array'];
}
