@extends('layouts.app')
@section('title', 'Checkout — Block Bord AI')
@section('content')
<section style="padding: 4rem 1.5rem; max-width: 600px; margin: 0 auto; color: #fff;">
  <h1 style="font-size: 2rem; font-weight: 800; text-align: center; margin-bottom: 1.5rem;">Upgrade to {{ strtoupper($plan) }}</h1>
  
  <div style="background: #1e1e2e; padding: 2rem; border-radius: 14px; border: 1px solid rgba(255,255,255,0.08); text-align: center;">
    <p style="color: #94a3b8; font-size: 1.1rem; margin-bottom: 1rem;">Total Amount</p>
    <div style="font-size: 3rem; font-weight: 900; color: #6366f1; margin-bottom: 2rem;">₹{{ number_format($amount / 100, 2) }}</div>

    <button id="payBtn" style="width: 100%; padding: 1rem; background: #6366f1; color: #fff; font-size: 1.1rem; font-weight: 700; border: none; border-radius: 10px; cursor: pointer;">Proceed with Razorpay</button>
  </div>
</section>

@section('extra_scripts')
<script src="https://checkout.razorpay.com/v1/checkout.js"></script>
<script>
document.getElementById('payBtn').addEventListener('click', async function() {
  try {
    const res = await fetch('{{ route("payments.create-order") }}', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-TOKEN': '{{ csrf_token() }}'
      },
      body: JSON.stringify({ plan: '{{ $plan }}' })
    });
    const result = await res.json();
    if(!result.success) {
      alert(result.message || 'Failed to initialize order');
      return;
    }

    const options = {
      key: '{{ env("RAZORPAY_KEY_ID", "rzp_test_mockkey") }}',
      amount: result.data.amount,
      currency: result.data.currency,
      name: 'Block Bord AI',
      description: 'Subscription Plan Upgrade',
      order_id: result.data.razorpay_order_id,
      handler: async function (response) {
        const verifyRes = await fetch('{{ route("payments.verify") }}', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-CSRF-TOKEN': '{{ csrf_token() }}'
          },
          body: JSON.stringify(response)
        });
        const verifyData = await verifyRes.json();
        alert(verifyData.message);
        if(verifyData.success) window.location.href = '{{ route("dashboard") }}';
      }
    };
    const rzp = new Razorpay(options);
    rzp.open();
  } catch(e) {
    console.error(e);
  }
});
</script>
@endsection
@endsection
