<?php

namespace App\Services\Payments;

use App\Models\Payment;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;
use RuntimeException;

class RazorpayService
{
    protected string $key;
    protected string $secret;
    protected string $webhookSecret;

    public function __construct()
    {
        $this->key = (string) config('services.razorpay.key', '');
        $this->secret = (string) config('services.razorpay.secret', '');
        $this->webhookSecret = (string) config('services.razorpay.webhook_secret', '');
    }

    public function createOrder(User $user, string $plan, int $amountPaise): array
    {
        $this->assertApiCredentials();
        if ($amountPaise < 1) {
            throw new RuntimeException('Order amount must be positive.');
        }

        $response = Http::timeout(15)
            ->withBasicAuth($this->key, $this->secret)
            ->post('https://api.razorpay.com/v1/orders', [
                'amount' => $amountPaise,
                'currency' => 'INR',
                'receipt' => 'bb_' . $user->id . '_' . bin2hex(random_bytes(8)),
                'notes' => [
                    'user_id' => (string) $user->id,
                    'plan' => $plan,
                ],
            ]);

        if (
            !$response->successful()
            || !$response->json('id')
            || (int) $response->json('amount') !== $amountPaise
            || $response->json('currency') !== 'INR'
        ) {
            Log::error('Razorpay order creation failed', ['status' => $response->status()]);
            throw new RuntimeException('Payment provider could not create the order.');
        }

        $orderId = (string) $response->json('id');
        Payment::create([
            'user_id' => $user->id,
            'plan' => $plan,
            'amount' => $amountPaise,
            'currency' => 'INR',
            'razorpay_order_id' => $orderId,
            'status' => 'created',
        ]);

        return [
            'razorpay_order_id' => $orderId,
            'amount' => $amountPaise,
            'currency' => 'INR',
            'key_id' => $this->key,
        ];
    }

    public function verifySignature(string $orderId, string $paymentId, string $signature): bool
    {
        if ($this->secret === '') {
            return false;
        }

        $expectedSignature = hash_hmac('sha256', $orderId . '|' . $paymentId, $this->secret);
        return hash_equals($expectedSignature, $signature);
    }

    public function hasApiCredentials(): bool
    {
        return $this->key !== '' && $this->secret !== '';
    }

    public function hasWebhookSecret(): bool
    {
        return $this->webhookSecret !== '';
    }

    public function verifyWebhookSignature(string $body, string $signature): bool
    {
        if ($this->webhookSecret === '') {
            return false;
        }

        $expectedSignature = hash_hmac('sha256', $body, $this->webhookSecret);
        return hash_equals($expectedSignature, $signature);
    }

    public function activateSubscription(Payment $payment, string $paymentId, ?string $signature): bool
    {
        return DB::transaction(function () use ($payment, $paymentId, $signature) {
            $lockedPayment = Payment::whereKey($payment->id)->lockForUpdate()->firstOrFail();
            if ($lockedPayment->status === 'paid') {
                return true;
            }

            $lockedPayment->razorpay_payment_id = $paymentId;
            $lockedPayment->razorpay_signature = $signature;
            $lockedPayment->status = 'paid';
            $lockedPayment->save();

            $user = User::whereKey($lockedPayment->user_id)->lockForUpdate()->firstOrFail();
            $user->plan = $lockedPayment->plan;
            $user->is_pro = true;
            $user->save();

            Log::info("User #{$user->id} upgraded to plan '{$lockedPayment->plan}' via Razorpay payment.");
            return true;
        });
    }

    private function assertApiCredentials(): void
    {
        if ($this->key === '' || $this->secret === '') {
            throw new RuntimeException('Razorpay API credentials are not configured.');
        }
    }
}
