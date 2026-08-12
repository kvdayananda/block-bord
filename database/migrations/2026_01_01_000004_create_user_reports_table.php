<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('user_reports', function (Blueprint $table) {
            $table->id();
            $table->text('reported_url');
            $table->string('reported_domain', 255)->nullable()->index();
            $table->text('description')->nullable();
            $table->string('status', 50)->default('pending'); // pending | reviewed | confirmed | dismissed
            $table->foreignId('user_id')->nullable()->constrained('users')->onDelete('cascade');
            $table->timestamps();

            $table->index('created_at');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('user_reports');
    }
};
