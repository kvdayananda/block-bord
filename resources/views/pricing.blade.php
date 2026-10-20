@extends('layouts.app')

@section('title', 'Pricing & Protection Plans — Block Bord AI')

@section('content')
<section style="padding: 4rem 1.5rem 6rem; max-width: 1240px; margin: 0 auto; text-align: center; color: #fff;">
  
  <span style="background: rgba(99, 102, 241, 0.15); color: #a5b4fc; padding: 0.5rem 1rem; border-radius: 9999px; font-size: 0.85rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; border: 1px solid rgba(99, 102, 241, 0.3);">
    💳 Transparent SaaS Protection Plans
  </span>
  
  <h1 style="font-size: 3.25rem; font-weight: 900; margin-top: 1rem; margin-bottom: 0.75rem; background: linear-gradient(135deg, #ffffff 0%, #a5b4fc 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
    Simple Plans For Every Security Need
  </h1>
  <p style="color: #94a3b8; font-size: 1.15rem; max-width: 650px; margin: 0 auto 3.5rem;">
    No hidden fees. Instant activation. Upgrade or cancel anytime with full money-back guarantee.
  </p>

  <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 2.25rem; text-align: left;">
    
    <!-- Free Tier -->
    <div style="background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(20px); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 24px; padding: 3rem 2.25rem; display: flex; flex-direction: column; justify-content: space-between;">
      <div>
        <div style="font-size: 0.875rem; font-weight: 700; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem;">Community</div>
        <h3 style="font-size: 1.75rem; font-weight: 800; margin-bottom: 0.5rem;">Free Shield</h3>
        <p style="color: #64748b; font-size: 0.925rem; margin-bottom: 1.75rem;">Basic link scanning for personal browsing.</p>

        <div style="font-size: 3rem; font-weight: 900; color: #fff; margin-bottom: 2rem;">
          ₹0 <span style="font-size: 1rem; color: #64748b; font-weight: 600;">/ month</span>
        </div>

        <ul style="display: flex; flex-direction: column; gap: 14px; margin-bottom: 2.5rem; color: #cbd5e1; font-size: 0.95rem; list-style: none; padding: 0;">
          <li style="display: flex; align-items: center; gap: 10px;">
            <span style="color: #10b981; font-weight: 800;">✓</span> 20 URL Scans per month
          </li>
          <li style="display: flex; align-items: center; gap: 10px;">
            <span style="color: #10b981; font-weight: 800;">✓</span> Basic Heuristic Scam Detection
          </li>
          <li style="display: flex; align-items: center; gap: 10px;">
            <span style="color: #10b981; font-weight: 800;">✓</span> Chrome Extension Access
          </li>
          <li style="display: flex; align-items: center; gap: 10px;">
            <span style="color: #f59e0b; font-weight: 800;">✓</span> Standard Ads Included
          </li>
          <li style="display: flex; align-items: center; gap: 10px; opacity: 0.4;">
            <span>✕</span> Gemini AI Copilot
          </li>
          <li style="display: flex; align-items: center; gap: 10px; opacity: 0.4;">
            <span>✕</span> Dark Web Leak Alerts
          </li>
        </ul>
      </div>

      <a href="{{ route('register') }}" style="display: block; text-align: center; padding: 1rem; background: #1e293b; color: #fff; border-radius: 12px; font-weight: 700; text-decoration: none; border: 1px solid rgba(255,255,255,0.1); transition: all 0.2s ease;">
        Get Started Free
      </a>
    </div>

    <!-- Pro Shield (Popular) -->
    <div style="background: linear-gradient(145deg, rgba(26, 27, 59, 0.9) 0%, rgba(15, 23, 42, 0.95) 100%); backdrop-filter: blur(20px); border: 2px solid #6366f1; border-radius: 24px; padding: 3rem 2.25rem; display: flex; flex-direction: column; justify-content: space-between; position: relative; box-shadow: 0 20px 50px rgba(99, 102, 241, 0.25);">
      <span style="position: absolute; top: -14px; right: 24px; background: linear-gradient(135deg, #6366f1 0%, #d946ef 100%); color: #fff; font-size: 0.75rem; font-weight: 800; padding: 5px 14px; border-radius: 9999px; text-transform: uppercase; letter-spacing: 0.05em; box-shadow: 0 4px 15px rgba(99, 102, 241, 0.4);">
        ★ MOST POPULAR
      </span>

      <div>
        <div style="font-size: 0.875rem; font-weight: 700; color: #a5b4fc; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem;">Professional</div>
        <h3 style="font-size: 1.75rem; font-weight: 800; margin-bottom: 0.5rem;">Pro Shield</h3>
        <p style="color: #94a3b8; font-size: 0.925rem; margin-bottom: 1.75rem;">Full AI cyber threat protection for active users.</p>

        <div style="font-size: 3rem; font-weight: 900; color: #fff; margin-bottom: 2rem;">
          ₹999 <span style="font-size: 1rem; color: #a5b4fc; font-weight: 600;">/ month</span>
        </div>

        <ul style="display: flex; flex-direction: column; gap: 14px; margin-bottom: 2.5rem; color: #f8fafc; font-size: 0.95rem; list-style: none; padding: 0;">
          <li style="display: flex; align-items: center; gap: 10px;">
            <span style="color: #10b981; font-weight: 800;">✓</span> <strong>Unlimited</strong> URL & IP Threat Scans
          </li>
          <li style="display: flex; align-items: center; gap: 10px;">
            <span style="color: #10b981; font-weight: 800;">✓</span> Advanced Gemini 2.5 & OpenAI Engine
          </li>
          <li style="display: flex; align-items: center; gap: 10px;">
            <span style="color: #10b981; font-weight: 800;">✓</span> Dark Web & Password Leak Alerts
          </li>
          <li style="display: flex; align-items: center; gap: 10px;">
            <span style="color: #10b981; font-weight: 800;">✓</span> <strong>100% Ad-Free Experience</strong>
          </li>
          <li style="display: flex; align-items: center; gap: 10px;">
            <span style="color: #10b981; font-weight: 800;">✓</span> Priority Extension Auto-Block
          </li>
          <li style="display: flex; align-items: center; gap: 10px;">
            <span style="color: #10b981; font-weight: 800;">✓</span> Standard API Key (100 req/day limit)
          </li>
        </ul>
      </div>

      <a href="{{ route('checkout', ['plan' => 'pro']) }}" style="display: block; text-align: center; padding: 1.1rem; background: linear-gradient(135deg, #6366f1 0%, #d946ef 100%); color: #fff; border-radius: 12px; font-weight: 800; text-decoration: none; box-shadow: 0 8px 24px rgba(99, 102, 241, 0.4); transition: all 0.2s ease;">
        Upgrade To Pro Shield →
      </a>
    </div>

    <!-- Enterprise / Business Tier -->
    <div style="background: rgba(15, 23, 42, 0.6); backdrop-filter: blur(20px); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 24px; padding: 3rem 2.25rem; display: flex; flex-direction: column; justify-content: space-between;">
      <div>
        <div style="font-size: 0.875rem; font-weight: 700; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem;">Corporate</div>
        <h3 style="font-size: 1.75rem; font-weight: 800; margin-bottom: 0.5rem;">Enterprise</h3>
        <p style="color: #64748b; font-size: 0.925rem; margin-bottom: 1.75rem;">Tailored for SOC teams, startups, and SMBs.</p>

        <div style="font-size: 3rem; font-weight: 900; color: #fff; margin-bottom: 2rem;">
          ₹2,499 <span style="font-size: 1rem; color: #64748b; font-weight: 600;">/ month</span>
        </div>

        <ul style="display: flex; flex-direction: column; gap: 14px; margin-bottom: 2.5rem; color: #cbd5e1; font-size: 0.95rem; list-style: none; padding: 0;">
          <li style="display: flex; align-items: center; gap: 10px;">
            <span style="color: #10b981; font-weight: 800;">✓</span> Everything in Pro Shield
          </li>
          <li style="display: flex; align-items: center; gap: 10px;">
            <span style="color: #10b981; font-weight: 800;">✓</span> High-Rate Limit API Keys (10k req/day limit)
          </li>
          <li style="display: flex; align-items: center; gap: 10px;">
            <span style="color: #10b981; font-weight: 800;">✓</span> Custom Blacklist/Whitelist Sync
          </li>
          <li style="display: flex; align-items: center; gap: 10px;">
            <span style="color: #10b981; font-weight: 800;">✓</span> SOC Analytics Dashboard
          </li>
          <li style="display: flex; align-items: center; gap: 10px;">
            <span style="color: #10b981; font-weight: 800;">✓</span> 24/7 Priority Security Engineer Support
          </li>
        </ul>
      </div>

      <a href="{{ route('checkout', ['plan' => 'business']) }}" style="display: block; text-align: center; padding: 1rem; background: #1e293b; color: #fff; border-radius: 12px; font-weight: 700; text-decoration: none; border: 1px solid rgba(255,255,255,0.1); transition: all 0.2s ease;">
        Get Enterprise →
      </a>
    </div>

  </div>
</section>
@endsection
