<?php

namespace App\Http\Controllers;

use App\Services\Payments\RazorpayService;
use App\Models\Payment;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

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

        $plan = $request->input('plan', 'pro');
        $amounts = [
            'starter' => 49900,
            'pro' => 99900,
            'business' => 249900
        ];
        $amount = $amounts[$plan] ?? 99900;

        $orderData = $this->razorpay->createOrder($user, $plan, $amount);

        return response()->json([
            'success' => true,
            'data' => $orderData,
        ]);
    }

    public function verifyPayment(Request $request)
    {
        $orderId = $request->input('razorpay_order_id');
        $paymentId = $request->input('razorpay_payment_id');
        $signature = $request->input('razorpay_signature');

        $payment = Payment::where('razorpay_order_id', $orderId)->first();
        if (!$payment) {
            return response()->json(['success' => false, 'message' => 'Order not found'], 404);
        }

        $isValid = $this->razorpay->verifySignature($orderId, $paymentId, $signature);
        if ($isValid) {
            $this->razorpay->activateSubscription($payment, $paymentId, $signature);
            return response()->json([
                'success' => true,
                'message' => 'Payment verified successfully. Subscription activated!',
            ]);
        }

        $payment->status = 'failed';
        $payment->save();

        return response()->json(['success' => false, 'message' => 'Invalid payment signature'], 400);
    }

    public function webhook(Request $request)
    {
        // Razorpay Webhook listener
        $payload = $request->all();
        return response()->json(['success' => true, 'status' => 'processed']);
    }
}
