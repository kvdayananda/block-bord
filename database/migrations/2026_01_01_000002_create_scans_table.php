<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('scans', function (Blueprint $table) {
            $table->id();
            $table->text('content');
            $table->string('url_hash', 64)->nullable()->index();
            $table->double('risk_score', 8, 2)->default(0.0);
            $table->string('risk_level', 50);
            $table->text('reasons')->nullable(); // JSON string
            $table->string('category', 100)->nullable();
            $table->string('scam_intent', 100)->nullable();
            $table->foreignId('user_id')->nullable()->constrained('users')->onDelete('cascade');
            $table->timestamps();

            $table->index(['user_id', 'created_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('scans');
    }
};
