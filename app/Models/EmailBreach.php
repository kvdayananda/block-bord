<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class EmailBreach extends Model
{
    use HasFactory;

    protected $guarded = [];

    protected $casts = ['breach_date' => 'date'];
}
