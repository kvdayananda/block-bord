<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class ToolUsage extends Model
{
    use HasFactory;

    protected $guarded = [];

    protected $table = 'tool_usage';
}
