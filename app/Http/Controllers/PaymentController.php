<?php

namespace App\Http\Controllers;

use App\Services\Payments\RazorpayService;
use App\Models\Payment;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Http\Client\ConnectionException;
use RuntimeException;

class PaymentController extends Controller
{
    protected RazorpayService $razorpay;

    public function __construct(RazorpayService $razorpay)
    {
        $this->razorpay = $razorpay;
    }

    public function showCheckout(Request $request)
    {
        $plan = $request->query('plan', 'pro');
        $amounts = [
            'starter' => 49900, // INR 499 in paise
            'pro' => 99900,     // INR 999 in paise
            'business' => 249900 // INR 2499 in paise
        ];

        $amount = $amounts[$plan] ?? 99900;
        return view('checkout', ['plan' => $plan, 'amount' => $amount]);
    }

    public function createOrder(Request $request)
    {
        $user = Auth::user();
        if (!$user) {
            return response()->json(['success' => false, 'message' => 'Unauthenticated'], 401);
        }

        $validated = $request->validate([
            'plan' => ['required', 'in:starter,pro,business'],
        ]);
        $plan = $validated['plan'];
        $amounts = [
            'starter' => 49900,
            'pro' => 99900,
            'business' => 249900
        ];
        $amount = $amounts[$plan];
        try {
            $orderData = $this->razorpay->createOrder($user, $plan, $amount);
        } catch (ConnectionException | RuntimeException $exception) {
            Log::error('Unable to create Razorpay order.', ['message' => $exception->getMessage()]);
            return response()->json([
                'success' => false,
                'message' => 'Payment provider is unavailable or not configured.',
            ], 502);
        }

        return response()->json([
            'success' => true,
            'data' => $orderData,
        ]);
    }

    public function verifyPayment(Request $request)
    {
        $validated = $request->validate([
            'razorpay_order_id' => ['required', 'string'],
            'razorpay_payment_id' => ['required', 'string'],
            'razorpay_signature' => ['required', 'string'],
        ]);
        $orderId = $validated['razorpay_order_id'];
        $paymentId = $validated['razorpay_payment_id'];
        $signature = $validated['razorpay_signature'];

        $payment = Payment::where('razorpay_order_id', $orderId)
            ->where('user_id', Auth::id())
            ->first();
        if (!$payment) {
            return response()->json(['success' => false, 'message' => 'Order not found'], 404);
        }

        if ($payment->status === 'paid') {
            return response()->json(['success' => true, 'message' => 'Payment was already verified.']);
        }
        if ($payment->status !== 'created') {
            return response()->json(['success' => false, 'message' => 'Order is not payable'], 409);
        }

        if (!$this->razorpay->hasApiCredentials()) {
            Log::error('Razorpay API credentials are not configured for payment verification.');
            return response()->json(['success' => false, 'message' => 'Payment verification is not configured'], 503);
        }

        $isValid = $this->razorpay->verifySignature($orderId, $paymentId, $signature);
        if ($isValid) {
            $this->razorpay->activateSubscription($payment, $paymentId, $signature);
            return response()->json([
                'success' => true,
                'message' => 'Payment verified successfully. Subscription activated!',
            ]);
        }

        return response()->json(['success' => false, 'message' => 'Invalid payment signature'], 400);
    }

    public function webhook(Request $request)
    {
        $signature = (string) $request->header('X-Razorpay-Signature', '');
        $body = $request->getContent();

        if ($signature === '') {
            return response()->json(['success' => false, 'message' => 'Webhook signature is required'], 400);
        }
        if (!$this->razorpay->hasWebhookSecret()) {
            Log::error('Razorpay webhook secret is not configured.');
            return response()->json(['success' => false, 'message' => 'Webhook processing is not configured'], 503);
        }
        if (!$this->razorpay->verifyWebhookSignature($body, $signature)) {
            Log::warning('Razorpay webhook signature validation failed or is not configured.');
            return response()->json(['success' => false, 'message' => 'Invalid webhook signature'], 400);
        }

        $event = $request->input('event');
        $payload = $request->input('payload', []);
        Log::info('Razorpay webhook event received.', ['event' => $event]);

        if ($event === 'payment.captured' || $event === 'order.paid') {
            $orderId = $payload['payment']['entity']['order_id']
                ?? $payload['order']['entity']['id']
                ?? null;
            $paymentId = $payload['payment']['entity']['id']
                ?? $payload['order']['entity']['payment_id']
                ?? null;
            $paidAmount = $payload['payment']['entity']['amount']
                ?? $payload['order']['entity']['amount_paid']
                ?? null;
            $currency = $payload['payment']['entity']['currency']
                ?? $payload['order']['entity']['currency']
                ?? null;

            if ($orderId && $paymentId) {
                $payment = Payment::where('razorpay_order_id', $orderId)->first();
                if (
                    $payment
                    && $payment->status !== 'paid'
                    && (int) $paidAmount === (int) $payment->amount
                    && $currency === $payment->currency
                ) {
                    $this->razorpay->activateSubscription($payment, $paymentId, null);
                } elseif ($payment && $payment->status !== 'paid') {
                    Log::warning('Razorpay webhook amount or currency did not match the local order.');
                }
            }
        }

        return response()->json(['success' => true, 'status' => 'processed']);
    }
}
