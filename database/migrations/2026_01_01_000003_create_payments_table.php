<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('payments', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained('users')->onDelete('cascade');
            $table->string('plan', 50);
            $table->integer('amount'); // paise
            $table->string('currency', 10)->default('INR');
            $table->string('razorpay_order_id', 255)->index();
            $table->string('razorpay_payment_id', 255)->nullable();
            $table->string('razorpay_signature', 255)->nullable();
            $table->string('status', 50)->default('created'); // created | paid | failed
            $table->timestamps();

            $table->index('created_at');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('payments');
    }
};
