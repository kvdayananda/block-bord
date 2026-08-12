@extends('layouts.app')

@section('title', 'Block Bord AI — Enterprise AI Cybersecurity')

@section('content')
<section class="hero-section">
  <div class="hero-container" style="max-width: 1200px; margin: 0 auto; padding: 4rem 1.5rem; text-align: center;">
    <span class="badge" style="background: rgba(99, 102, 241, 0.15); color: #818cf8; padding: 0.5rem 1rem; border-radius: 9999px; font-size: 0.875rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; border: 1px solid rgba(99, 102, 241, 0.3);">
      🚀 Next-Gen Phishing & Threat Protection
    </span>
    
    <h1 style="font-size: 3.5rem; font-weight: 900; margin-top: 1.5rem; line-height: 1.1; background: linear-gradient(135deg, #ffffff 0%, #a5b4fc 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
      AI-Powered Cyber Intelligence Platform
    </h1>
    
    <p style="font-size: 1.25rem; color: #94a3b8; max-width: 750px; margin: 1.5rem auto 2.5rem; line-height: 1.6;">
      Detect phishing URLs, malicious IPs, fake UPI payment QR codes, and dark-web leaks in real-time with state-of-the-art XGBoost machine learning and multi-provider AI engine.
    </p>

    <!-- Interactive URL Quick Scanner -->
    <div class="scanner-card" style="background: #1e1e2e; border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 16px; padding: 2rem; max-width: 700px; margin: 0 auto; box-shadow: 0 20px 40px rgba(0,0,0,0.5);">
      <form action="{{ route('scan') }}" method="POST" id="quickScanForm">
        @csrf
        <div style="display: flex; gap: 0.75rem;">
          <input type="text" name="url" placeholder="Enter website URL, IP address, or suspicious link..." required style="flex: 1; padding: 1rem 1.25rem; border-radius: 10px; border: 1px solid #33334d; background: #11111b; color: #fff; font-size: 1rem; outline: none;">
          <button type="submit" style="padding: 1rem 2rem; background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%); color: #fff; font-weight: 700; border: none; border-radius: 10px; cursor: pointer; transition: transform 0.2s, box-shadow 0.2s;">
            Scan Link
          </button>
        </div>
      </form>
      <div id="scanResult" style="margin-top: 1.5rem; display: none; text-align: left; background: #11111b; padding: 1.25rem; border-radius: 10px;"></div>
    </div>
  </div>
</section>

<!-- Features Grid -->
<section style="background: #11111b; padding: 5rem 1.5rem;">
  <div style="max-width: 1200px; margin: 0 auto;">
    <h2 style="text-align: center; font-size: 2.25rem; font-weight: 800; color: #fff; margin-bottom: 3rem;">
      Comprehensive Security Toolsuite
    </h2>
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 2rem;">
      <div style="background: #1e1e2e; padding: 2rem; border-radius: 14px; border: 1px solid rgba(255,255,255,0.08);">
        <div style="font-size: 2.5rem; margin-bottom: 1rem;">🔍</div>
        <h3 style="color: #fff; font-size: 1.25rem; margin-bottom: 0.5rem;">URL & Domain Scanner</h3>
        <p style="color: #94a3b8; font-size: 0.95rem; line-height: 1.5;">Analyzes domain age, SSL status, WHOIS records, and DNS heuristics using AI.</p>
      </div>
      <div style="background: #1e1e2e; padding: 2rem; border-radius: 14px; border: 1px solid rgba(255,255,255,0.08);">
        <div style="font-size: 2.5rem; margin-bottom: 1rem;">🤖</div>
        <h3 style="color: #fff; font-size: 1.25rem; margin-bottom: 0.5rem;">AI Cyber Assistant</h3>
        <p style="color: #94a3b8; font-size: 0.95rem; line-height: 1.5;">Conversational assistant powered by Gemini & OpenAI with automatic fallback.</p>
      </div>
      <div style="background: #1e1e2e; padding: 2rem; border-radius: 14px; border: 1px solid rgba(255,255,255,0.08);">
        <div style="font-size: 2.5rem; margin-bottom: 1rem;">💸</div>
        <h3 style="color: #fff; font-size: 1.25rem; margin-bottom: 0.5rem;">UPI & Payment Guard</h3>
        <p style="color: #94a3b8; font-size: 0.95rem; line-height: 1.5;">Validates UPI payment IDs, VPA formats, and scam payment patterns before transfer.</p>
      </div>
      <div style="background: #1e1e2e; padding: 2rem; border-radius: 14px; border: 1px solid rgba(255,255,255,0.08);">
        <div style="font-size: 2.5rem; margin-bottom: 1rem;">🧩</div>
        <h3 style="color: #fff; font-size: 1.25rem; margin-bottom: 0.5rem;">Chrome Extension</h3>
        <p style="color: #94a3b8; font-size: 0.95rem; line-height: 1.5;">Real-time inline browser warnings and page element threat indicators.</p>
      </div>
    </div>
  </div>
</section>
@endsection
