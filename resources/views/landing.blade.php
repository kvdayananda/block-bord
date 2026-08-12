@extends('layouts.app')

@section('title', 'Block Bord AI — Next-Gen AI Cyber Threat Intelligence')

@section('content')
<!-- Hero Section -->
<section style="position: relative; padding: 5rem 1.5rem 6rem; overflow: hidden; background: radial-gradient(circle at 50% 20%, rgba(99, 102, 241, 0.18) 0%, rgba(6, 8, 20, 1) 70%);">
  <!-- Glowing Background Mesh Effect -->
  <div style="position: absolute; top: -100px; left: 50%; transform: translateX(-50%); width: 800px; height: 500px; background: radial-gradient(circle, rgba(99, 102, 241, 0.25) 0%, rgba(217, 70, 239, 0.15) 50%, transparent 80%); filter: blur(80px); pointer-events: none; z-index: 0;"></div>

  <div style="position: relative; z-index: 1; max-width: 1200px; margin: 0 auto; text-align: center;">
    
    <!-- Hero Badge -->
    <div style="display: inline-flex; align-items: center; gap: 8px; background: rgba(99, 102, 241, 0.12); color: #a5b4fc; padding: 0.6rem 1.2rem; border-radius: 9999px; font-size: 0.875rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.06em; border: 1px solid rgba(99, 102, 241, 0.3); box-shadow: 0 0 20px rgba(99, 102, 241, 0.2); margin-bottom: 2rem;">
      <span style="display: inline-block; width: 8px; height: 8px; background: #10b981; border-radius: 50%; box-shadow: 0 0 10px #10b981;"></span>
      AI Engine v5.0 Active — XGBoost & Gemini Multi-LLM Shield
    </div>
    
    <!-- Hero Headline -->
    <h1 style="font-size: 3.75rem; font-weight: 900; line-height: 1.1; margin-bottom: 1.5rem; background: linear-gradient(135deg, #ffffff 30%, #a5b4fc 70%, #d946ef 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; letter-spacing: -0.03em;">
      Autonomous AI Security<br>For Digital Assets & Links
    </h1>
    
    <!-- Hero Subtitle -->
    <p style="font-size: 1.25rem; color: #94a3b8; max-width: 780px; margin: 0 auto 3rem; line-height: 1.7;">
      Detect phishing URLs, scam domains, dark-web leaks, and malicious IPs in milliseconds. Powered by real-time XGBoost ML and conversational Gemini AI.
    </p>

    <!-- Multi-Tool Interactive Scanner Console -->
    <div style="background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(24px); -webkit-backdrop-filter: blur(24px); border: 1px solid rgba(99, 102, 241, 0.3); border-radius: 24px; padding: 2rem; max-width: 800px; margin: 0 auto; box-shadow: 0 25px 60px rgba(0, 0, 0, 0.6), 0 0 30px rgba(99, 102, 241, 0.15);">
      
      <!-- Scanner Tab Bar -->
      <div style="display: flex; gap: 8px; background: #0c0f24; padding: 6px; border-radius: 12px; margin-bottom: 1.5rem; border: 1px solid rgba(255,255,255,0.06);">
        <button type="button" class="tab-btn active" style="flex: 1; padding: 10px; border-radius: 8px; background: rgba(99, 102, 241, 0.25); color: #fff; font-weight: 700; font-size: 0.9rem; border: 1px solid rgba(99, 102, 241, 0.4);">🔗 URL Scanner</button>
        <button type="button" class="tab-btn" style="flex: 1; padding: 10px; border-radius: 8px; background: transparent; color: #94a3b8; font-weight: 600; font-size: 0.9rem; border: none;">🌐 Domain WHOIS</button>
        <button type="button" class="tab-btn" style="flex: 1; padding: 10px; border-radius: 8px; background: transparent; color: #94a3b8; font-weight: 600; font-size: 0.9rem; border: none;">📍 IP Intelligence</button>
      </div>

      <!-- Scan Form -->
      <form action="{{ route('scan') }}" method="POST" id="mainScanForm">
        @csrf
        <div style="display: flex; gap: 12px; position: relative;">
          <input type="text" name="url" placeholder="Paste website URL, IP address, or suspicious link to inspect..." required style="flex: 1; padding: 1.1rem 1.4rem; border-radius: 14px; border: 1.5px solid rgba(99, 102, 241, 0.3); background: #060814; color: #fff; font-size: 1rem; outline: none; transition: all 0.3s ease; box-shadow: inset 0 2px 4px rgba(0,0,0,0.5);">
          <button type="submit" style="padding: 1.1rem 2.2rem; background: linear-gradient(135deg, #6366f1 0%, #d946ef 100%); color: #fff; font-weight: 800; font-size: 1rem; border: none; border-radius: 14px; cursor: pointer; transition: all 0.3s ease; box-shadow: 0 8px 24px rgba(99, 102, 241, 0.4); white-space: nowrap;">
            ⚡ Analyze Now
          </button>
        </div>
      </form>

      <!-- Quick Samples -->
      <div style="display: flex; align-items: center; justify-content: center; gap: 12px; margin-top: 1.25rem; font-size: 0.85rem; color: #64748b;">
        <span>Try sample:</span>
        <button type="button" onclick="setScanInput('https://google.com')" style="color: #a5b4fc; background: rgba(99,102,241,0.1); padding: 3px 10px; border-radius: 6px; border: 1px solid rgba(99,102,241,0.2); font-size: 0.8rem; cursor: pointer;">google.com</button>
        <button type="button" onclick="setScanInput('http://secure-verify-bank-update.xyz')" style="color: #f87171; background: rgba(239,68,68,0.1); padding: 3px 10px; border-radius: 6px; border: 1px solid rgba(239,68,68,0.2); font-size: 0.8rem; cursor: pointer;">phishing-sample.xyz</button>
      </div>
    </div>
  </div>
</section>

<!-- Live Threat Intelligence Stats Ticker -->
<section style="background: #0c0f24; border-y: 1px solid rgba(99, 102, 241, 0.15); padding: 2.5rem 1.5rem;">
  <div style="max-width: 1200px; margin: 0 auto; display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 2rem; text-align: center;">
    <div>
      <div style="font-size: 2.5rem; font-weight: 900; color: #ffffff; background: linear-gradient(135deg, #6366f1 0%, #a5b4fc 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">50M+</div>
      <div style="color: #94a3b8; font-size: 0.9rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 4px;">URLs Scanned</div>
    </div>
    <div>
      <div style="font-size: 2.5rem; font-weight: 900; color: #ffffff; background: linear-gradient(135deg, #10b981 0%, #6ee7b7 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">99.85%</div>
      <div style="color: #94a3b8; font-size: 0.9rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 4px;">ML Detection Rate</div>
    </div>
    <div>
      <div style="font-size: 2.5rem; font-weight: 900; color: #ffffff; background: linear-gradient(135deg, #3b82f6 0%, #93c5fd 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">&lt;12ms</div>
      <div style="color: #94a3b8; font-size: 0.9rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 4px;">Analysis Latency</div>
    </div>
    <div>
      <div style="font-size: 2.5rem; font-weight: 900; color: #ffffff; background: linear-gradient(135deg, #d946ef 0%, #f472b6 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">24/7</div>
      <div style="color: #94a3b8; font-size: 0.9rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 4px;">Autonomous Monitoring</div>
    </div>
  </div>
</section>

<!-- Cyber Feature Showcase Grid -->
<section style="padding: 6rem 1.5rem; background: #060814;">
  <div style="max-width: 1200px; margin: 0 auto;">
    
    <div style="text-align: center; margin-bottom: 4rem;">
      <h2 style="font-size: 2.5rem; font-weight: 900; color: #fff; margin-bottom: 1rem;">Enterprise Cyber Defense Suite</h2>
      <p style="color: #94a3b8; font-size: 1.15rem; max-width: 650px; margin: 0 auto;">Multi-layered security tools built to protect users, domains, and payment data.</p>
    </div>

    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(340px, 1fr)); gap: 2rem;">
      
      <!-- Feature 1 -->
      <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(99, 102, 241, 0.18); border-radius: 20px; padding: 2.5rem; transition: all 0.3s ease; position: relative; overflow: hidden;" onmouseover="this.style.borderColor='rgba(99, 102, 241, 0.5)'; this.style.transform='translateY(-6px)';" onmouseout="this.style.borderColor='rgba(99, 102, 241, 0.18)'; this.style.transform='translateY(0)';">
        <div style="width: 56px; height: 56px; background: rgba(99, 102, 241, 0.15); border-radius: 14px; display: flex; align-items: center; justify-content: center; font-size: 1.75rem; margin-bottom: 1.5rem; border: 1px solid rgba(99,102,241,0.3);">
          🔍
        </div>
        <h3 style="font-size: 1.4rem; font-weight: 800; color: #fff; margin-bottom: 0.75rem;">URL Phishing Engine</h3>
        <p style="color: #94a3b8; line-height: 1.6; font-size: 0.95rem;">Extracts 30+ lexical features, entropy metrics, and SSL certificates to detect zero-day phishing sites before they harvest credentials.</p>
      </div>

      <!-- Feature 2 -->
      <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(99, 102, 241, 0.18); border-radius: 20px; padding: 2.5rem; transition: all 0.3s ease; position: relative; overflow: hidden;" onmouseover="this.style.borderColor='rgba(99, 102, 241, 0.5)'; this.style.transform='translateY(-6px)';" onmouseout="this.style.borderColor='rgba(99, 102, 241, 0.18)'; this.style.transform='translateY(0)';">
        <div style="width: 56px; height: 56px; background: rgba(217, 70, 239, 0.15); border-radius: 14px; display: flex; align-items: center; justify-content: center; font-size: 1.75rem; margin-bottom: 1.5rem; border: 1px solid rgba(217, 70, 239, 0.3);">
          🤖
        </div>
        <h3 style="font-size: 1.4rem; font-weight: 800; color: #fff; margin-bottom: 0.75rem;">AI Cyber Copilot</h3>
        <p style="color: #94a3b8; line-height: 1.6; font-size: 0.95rem;">Conversational assistant powered by Gemini 2.5 Flash and OpenAI with automatic provider fallback for interactive scam analysis.</p>
      </div>

      <!-- Feature 3 -->
      <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(99, 102, 241, 0.18); border-radius: 20px; padding: 2.5rem; transition: all 0.3s ease; position: relative; overflow: hidden;" onmouseover="this.style.borderColor='rgba(99, 102, 241, 0.5)'; this.style.transform='translateY(-6px)';" onmouseout="this.style.borderColor='rgba(99, 102, 241, 0.18)'; this.style.transform='translateY(0)';">
        <div style="width: 56px; height: 56px; background: rgba(16, 185, 129, 0.15); border-radius: 14px; display: flex; align-items: center; justify-content: center; font-size: 1.75rem; margin-bottom: 1.5rem; border: 1px solid rgba(16, 185, 129, 0.3);">
          🔐
        </div>
        <h3 style="font-size: 1.4rem; font-weight: 800; color: #fff; margin-bottom: 0.75rem;">Breach & Password Checker</h3>
        <p style="color: #94a3b8; line-height: 1.6; font-size: 0.95rem;">Queries HaveIBeenPwned's 10B+ leaked password database via k-Anonymity SHA-1 hash prefixes to keep user credentials safe.</p>
      </div>

      <!-- Feature 4 -->
      <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(99, 102, 241, 0.18); border-radius: 20px; padding: 2.5rem; transition: all 0.3s ease; position: relative; overflow: hidden;" onmouseover="this.style.borderColor='rgba(99, 102, 241, 0.5)'; this.style.transform='translateY(-6px)';" onmouseout="this.style.borderColor='rgba(99, 102, 241, 0.18)'; this.style.transform='translateY(0)';">
        <div style="width: 56px; height: 56px; background: rgba(245, 158, 11, 0.15); border-radius: 14px; display: flex; align-items: center; justify-content: center; font-size: 1.75rem; margin-bottom: 1.5rem; border: 1px solid rgba(245, 158, 11, 0.3);">
          🌐
        </div>
        <h3 style="font-size: 1.4rem; font-weight: 800; color: #fff; margin-bottom: 0.75rem;">Domain & IP Intelligence</h3>
        <p style="color: #94a3b8; line-height: 1.6; font-size: 0.95rem;">Resolves WHOIS registrar details, DNS records (A, MX, NS, TXT), SSL certificates, and geolocation telemetry.</p>
      </div>

      <!-- Feature 5 -->
      <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(99, 102, 241, 0.18); border-radius: 20px; padding: 2.5rem; transition: all 0.3s ease; position: relative; overflow: hidden;" onmouseover="this.style.borderColor='rgba(99, 102, 241, 0.5)'; this.style.transform='translateY(-6px)';" onmouseout="this.style.borderColor='rgba(99, 102, 241, 0.18)'; this.style.transform='translateY(0)';">
        <div style="width: 56px; height: 56px; background: rgba(59, 130, 246, 0.15); border-radius: 14px; display: flex; align-items: center; justify-content: center; font-size: 1.75rem; margin-bottom: 1.5rem; border: 1px solid rgba(59, 130, 246, 0.3);">
          🧩
        </div>
        <h3 style="font-size: 1.4rem; font-weight: 800; color: #fff; margin-bottom: 0.75rem;">Chrome Browser Extension</h3>
        <p style="color: #94a3b8; line-height: 1.6; font-size: 0.95rem;">Manifest V3 extension provides real-time browser warning overlays and inline link threat badges while you navigate.</p>
      </div>

      <!-- Feature 6 -->
      <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(99, 102, 241, 0.18); border-radius: 20px; padding: 2.5rem; transition: all 0.3s ease; position: relative; overflow: hidden;" onmouseover="this.style.borderColor='rgba(99, 102, 241, 0.5)'; this.style.transform='translateY(-6px)';" onmouseout="this.style.borderColor='rgba(99, 102, 241, 0.18)'; this.style.transform='translateY(0)';">
        <div style="width: 56px; height: 56px; background: rgba(239, 68, 68, 0.15); border-radius: 14px; display: flex; align-items: center; justify-content: center; font-size: 1.75rem; margin-bottom: 1.5rem; border: 1px solid rgba(239, 68, 68, 0.3);">
          💳
        </div>
        <h3 style="font-size: 1.4rem; font-weight: 800; color: #fff; margin-bottom: 0.75rem;">Razorpay Subscription Engine</h3>
        <p style="color: #94a3b8; line-height: 1.6; font-size: 0.95rem;">Seamless subscription checkout with automated HMAC-SHA256 signature verification and API key entitlement upgrades.</p>
      </div>

    </div>
  </div>
</section>

<!-- Call to Action Section -->
<section style="padding: 5rem 1.5rem; background: linear-gradient(135deg, rgba(99, 102, 241, 0.15) 0%, rgba(217, 70, 239, 0.1) 100%); text-align: center; border-t: 1px solid rgba(99, 102, 241, 0.2);">
  <div style="max-width: 800px; margin: 0 auto;">
    <h2 style="font-size: 2.75rem; font-weight: 900; color: #fff; margin-bottom: 1.25rem;">Start Protecting Your Digital Life Today</h2>
    <p style="color: #94a3b8; font-size: 1.15rem; margin-bottom: 2.5rem;">Join thousands of security-conscious professionals using Block Bord AI for instant threat detection.</p>
    <a href="{{ route('register') }}" style="display: inline-block; padding: 1.1rem 2.5rem; background: linear-gradient(135deg, #6366f1 0%, #d946ef 100%); color: #fff; font-weight: 800; font-size: 1.05rem; border-radius: 14px; text-decoration: none; box-shadow: 0 10px 30px rgba(99, 102, 241, 0.4); transition: transform 0.2s;">
      Get Started For Free →
    </a>
  </div>
</section>

<script>
function setScanInput(val) {
  document.querySelector('input[name="url"]').value = val;
}
</script>
@endsection
