@extends('layouts.app')

@section('title', 'Pricing Plans — Block Bord AI')

@section('content')
<section style="padding: 4rem 1.5rem; max-width: 1200px; margin: 0 auto; text-align: center;">
  <h1 style="font-size: 3rem; font-weight: 900; color: #fff; margin-bottom: 1rem;">Simple, Transparent Pricing</h1>
  <p style="color: #94a3b8; font-size: 1.2rem; max-width: 600px; margin: 0 auto 3rem;">Choose the right protection plan for your browsing and security needs.</p>

  <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 2rem;">
    <!-- Free Plan -->
    <div style="background: #1e1e2e; border: 1px solid rgba(255,255,255,0.1); border-radius: 16px; padding: 2.5rem 2rem; text-align: left;">
      <h3 style="color: #fff; font-size: 1.5rem; margin-bottom: 0.5rem;">Free Tier</h3>
      <p style="color: #94a3b8; margin-bottom: 1.5rem;">Basic link scanning and threat reports.</p>
      <div style="font-size: 2.5rem; font-weight: 800; color: #fff; margin-bottom: 1.5rem;">₹0 <span style="font-size: 1rem; color: #94a3b8;">/month</span></div>
      <ul style="color: #cbd5e1; line-height: 2; margin-bottom: 2rem; list-style: none; padding: 0;">
        <td>✅ 20 URL Scans / month</td>
        <td>✅ Basic AI Assistant</td>
        <td>✅ Chrome Extension Access</td>
      </ul>
      <a href="{{ route('register') }}" style="display: block; text-align: center; background: #33334d; color: #fff; padding: 0.85rem; border-radius: 10px; font-weight: 600; text-decoration: none;">Get Started Free</a>
    </div>

    <!-- Pro Plan -->
    <div style="background: linear-gradient(135deg, #1e1e2e 0%, #2d2b55 100%); border: 2px solid #6366f1; border-radius: 16px; padding: 2.5rem 2rem; text-align: left; position: relative;">
      <span style="position: absolute; top: -12px; right: 20px; background: #6366f1; color: #fff; font-size: 0.75rem; font-weight: 800; padding: 0.25rem 0.75rem; border-radius: 9999px; text-transform: uppercase;">POPULAR</span>
      <h3 style="color: #fff; font-size: 1.5rem; margin-bottom: 0.5rem;">Pro Shield</h3>
      <p style="color: #94a3b8; margin-bottom: 1.5rem;">For active web users and freelancers.</p>
      <div style="font-size: 2.5rem; font-weight: 800; color: #fff; margin-bottom: 1.5rem;">₹999 <span style="font-size: 1rem; color: #94a3b8;">/month</span></div>
      <ul style="color: #cbd5e1; line-height: 2; margin-bottom: 2rem; list-style: none; padding: 0;">
        <td>✅ Unlimited URL & IP Scans</td>
        <td>✅ Advanced Gemini & OpenAI Engine</td>
        <td>✅ Real-Time Dark Web & Email Leak Alerts</td>
        <td>✅ Priority Extension Protection</td>
      </ul>
      <a href="{{ route('checkout', ['plan' => 'pro']) }}" style="display: block; text-align: center; background: #6366f1; color: #fff; padding: 0.85rem; border-radius: 10px; font-weight: 700; text-decoration: none;">Upgrade to Pro</a>
    </div>
  </div>
</section>
@endsection
