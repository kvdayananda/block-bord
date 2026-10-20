<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('email_breaches', function (Blueprint $table) {
            $table->id();
            $table->string('email')->index();
            $table->string('breach_name');
            $table->date('breach_date')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('email_breaches');
    }
};
