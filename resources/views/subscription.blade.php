@extends('layouts.app')

@section('title', 'Subscription & Tier Management — Block Bord AI')

@section('content')
<div style="display: flex; min-height: calc(100vh - 70px); background: #060814;">
  <x-sidebar />

  <main style="flex: 1; padding: 2.5rem; background: #060814; color: #fff;">

    <!-- Header Section -->
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2.5rem; flex-wrap: wrap; gap: 1rem;">
      <div>
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 6px;">
          <h1 style="font-size: 2.25rem; font-weight: 900; color: #fff; margin: 0;">Subscription & Tier</h1>
          <span style="background: linear-gradient(135deg, #6366f1, #d946ef); color: #fff; font-weight: 800; padding: 4px 14px; border-radius: 9999px; font-size: 0.8rem; text-transform: uppercase;">
            {{ $user->plan }} Tier Active
          </span>
        </div>
        <p style="color: #94a3b8; font-size: 0.975rem;">Manage your active cybersecurity quotas, enterprise API keys, and premium threat engines.</p>
      </div>

      <div style="display: flex; gap: 12px;">
        <a href="{{ route('checkout') }}" style="background: linear-gradient(135deg, #6366f1 0%, #d946ef 100%); color: #fff; padding: 0.85rem 1.6rem; border-radius: 12px; font-weight: 800; font-size: 0.925rem; text-decoration: none; box-shadow: 0 4px 20px rgba(99, 102, 241, 0.35);">
          ⚡ Upgrade to Pro
        </a>
      </div>
    </div>

    <!-- Active Quota Card -->
    <div style="background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(20px); border: 1px solid rgba(99, 102, 241, 0.25); border-radius: 20px; padding: 2rem; margin-bottom: 3rem;">
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.5rem;">

        <div>
          <span style="color: #94a3b8; font-size: 0.85rem; font-weight: 600;">Current Plan</span>
          <div style="font-size: 1.8rem; font-weight: 900; color: #fff; margin-top: 4px; text-transform: capitalize;">
            {{ $user->plan }} Plan
          </div>
          <div style="font-size: 0.8rem; color: #10b981; font-weight: 600; margin-top: 4px;">● Status: Active & Protected</div>
        </div>

        <div>
          <span style="color: #94a3b8; font-size: 0.85rem; font-weight: 600;">Daily Scan Limit</span>
          <div style="font-size: 1.8rem; font-weight: 900; color: #a5b4fc; margin-top: 4px;">
            {{ $user->is_pro ? 'Unlimited' : '50 Scans / day' }}
          </div>
          <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 4px;">Resets at midnight UTC</div>
        </div>

        <div>
          <span style="color: #94a3b8; font-size: 0.85rem; font-weight: 600;">AI Copilot Access</span>
          <div style="font-size: 1.8rem; font-weight: 900; color: #38bdf8; margin-top: 4px;">
            {{ $user->is_pro ? 'Gemini 1.5 Pro' : 'Gemini Flash' }}
          </div>
          <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 4px;">Neural risk diagnostics</div>
        </div>

        <div>
          <span style="color: #94a3b8; font-size: 0.85rem; font-weight: 600;">PDF Threat Reports</span>
          <div style="font-size: 1.8rem; font-weight: 900; color: #f472b6; margin-top: 4px;">
            {{ $user->is_pro ? 'Enterprise PDF' : 'Standard Web' }}
          </div>
          <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 4px;">Print & export ready</div>
        </div>

      </div>
    </div>

    <!-- Tier Comparison Grid -->
    <h3 style="font-size: 1.35rem; font-weight: 800; color: #fff; margin-bottom: 1.5rem;">
      Available Protection Tiers
    </h3>

    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.75rem; margin-bottom: 3rem;">

      <!-- Free Plan -->
      <div style="background: rgba(15, 23, 42, 0.75); border: 1px solid rgba(255,255,255,0.08); border-radius: 20px; padding: 2rem; display: flex; flex-direction: column; justify-content: space-between;">
        <div>
          <div style="font-size: 1.35rem; font-weight: 800; color: #fff; margin-bottom: 6px;">Free Starter</div>
          <div style="font-size: 2.25rem; font-weight: 900; color: #fff; margin-bottom: 1.25rem;">$0 <span style="font-size: 0.9rem; color: #64748b; font-weight: 600;">/ month</span></div>
          <ul style="list-style: none; padding: 0; margin: 0 0 2rem 0; display: flex; flex-direction: column; gap: 10px; font-size: 0.925rem; color: #cbd5e1;">
            <li>✓ 50 Threat Scans / day</li>
            <li>✓ URL & Domain Inspector</li>
            <li>✓ Password Strength & Breach Check</li>
            <li>✓ Chrome Extension Integration</li>
            <li style="color: #64748b;">✕ Unlimited AI Explanations</li>
            <li style="color: #64748b;">✕ High-throughput API Key</li>
          </ul>
        </div>
        <div>
          @if($user->plan === 'free')
            <button disabled style="width: 100%; padding: 0.85rem; border-radius: 12px; background: rgba(255,255,255,0.06); color: #94a3b8; border: 1px solid rgba(255,255,255,0.1); font-weight: 700;">Current Plan</button>
          @else
            <a href="#" style="display: block; text-align: center; width: 100%; padding: 0.85rem; border-radius: 12px; background: rgba(255,255,255,0.06); color: #fff; text-decoration: none; font-weight: 700;">Downgrade</a>
          @endif
        </div>
      </div>

      <!-- Pro Plan -->
      <div style="background: rgba(15, 23, 42, 0.95); border: 2px solid #6366f1; border-radius: 20px; padding: 2rem; display: flex; flex-direction: column; justify-content: space-between; box-shadow: 0 10px 40px rgba(99,102,241,0.25); position: relative;">
        <span style="position: absolute; top: -12px; right: 24px; background: linear-gradient(135deg, #6366f1, #d946ef); color: #fff; padding: 4px 12px; border-radius: 9999px; font-size: 0.75rem; font-weight: 800; text-transform: uppercase;">Most Popular</span>
        <div>
          <div style="font-size: 1.35rem; font-weight: 800; color: #fff; margin-bottom: 6px;">Pro Defense</div>
          <div style="font-size: 2.25rem; font-weight: 900; color: #fff; margin-bottom: 1.25rem;">$19 <span style="font-size: 0.9rem; color: #64748b; font-weight: 600;">/ month</span></div>
          <ul style="list-style: none; padding: 0; margin: 0 0 2rem 0; display: flex; flex-direction: column; gap: 10px; font-size: 0.925rem; color: #cbd5e1;">
            <li>✓ <strong>Unlimited</strong> URL & Content Scans</li>
            <li>✓ All 30 Security & Scam Protection Tools</li>
            <li>✓ Full PDF Threat Audit Export</li>
            <li>✓ Dedicated API Key & Quota</li>
            <li>✓ Priority Gemini AI Threat Analysis</li>
            <li>✓ Custom Domain Blacklist & Whitelist</li>
          </ul>
        </div>
        <div>
          @if($user->plan === 'pro')
            <button disabled style="width: 100%; padding: 0.85rem; border-radius: 12px; background: #10b981; color: #fff; border: none; font-weight: 700;">Active Plan</button>
          @else
            <a href="{{ route('checkout') }}" style="display: block; text-align: center; width: 100%; padding: 0.85rem; border-radius: 12px; background: linear-gradient(135deg, #6366f1, #d946ef); color: #fff; text-decoration: none; font-weight: 800; box-shadow: 0 4px 15px rgba(99,102,241,0.4);">Upgrade Now →</a>
          @endif
        </div>
      </div>

    </div>

  </main>
</div>
@endsection
