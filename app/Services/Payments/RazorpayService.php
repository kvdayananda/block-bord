<?php

namespace App\Services\Payments;

use App\Models\Payment;
use App\Models\User;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class RazorpayService
{
    protected string $key;
    protected string $secret;

    public function __construct()
    {
        $this->key = env('RAZORPAY_KEY', '');
        $this->secret = env('RAZORPAY_SECRET', '');
    }

    public function createOrder(User $user, string $plan, int $amountPaise): array
    {
        $orderId = 'order_' . strtolower(bin2hex(random_bytes(10)));

        $payment = Payment::create([
            'user_id' => $user->id,
            'plan' => $plan,
            'amount' => $amountPaise,
            'currency' => 'INR',
            'razorpay_order_id' => $orderId,
            'status' => 'created',
        ]);

        return [
            'id' => $orderId,
            'entity' => 'order',
            'amount' => $amountPaise,
            'currency' => 'INR',
            'status' => 'created',
            'key' => $this->key,
        ];
    }

    public function verifySignature(string $orderId, string $paymentId, string $signature): bool
    {
        $expectedSignature = hash_hmac('sha256', $orderId . '|' . $paymentId, $this->secret);
        return hash_equals($expectedSignature, $signature);
    }

    public function activateSubscription(Payment $payment, string $paymentId, string $signature): bool
    {
        $payment->razorpay_payment_id = $paymentId;
        $payment->razorpay_signature = $signature;
        $payment->status = 'paid';
        $payment->save();

        $user = $payment->user;
        $user->plan = $payment->plan;
        $user->is_pro = true;
        $user->save();

        Log::info("User #{$user->id} upgraded to plan '{$payment->plan}' via Razorpay Payment #{$paymentId}");

        return true;
    }
}
