@extends('layouts.app')

@section('title', 'Cyber Security Tools Suite — Block Bord AI')

@section('content')
<section style="padding: 4rem 1.5rem 6rem; max-width: 1240px; margin: 0 auto; color: #fff;">
  
  <div style="text-align: center; margin-bottom: 3.5rem;">
    <span style="background: rgba(99, 102, 241, 0.15); color: #a5b4fc; padding: 0.5rem 1rem; border-radius: 9999px; font-size: 0.85rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; border: 1px solid rgba(99, 102, 241, 0.3);">
      🧰 All-In-One Security Intelligence
    </span>
    <h1 style="font-size: 3rem; font-weight: 900; margin-top: 1rem; margin-bottom: 0.75rem; background: linear-gradient(135deg, #ffffff 0%, #a5b4fc 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
      Enterprise Security Tools Suite
    </h1>
    <p style="color: #94a3b8; font-size: 1.15rem; max-width: 650px; margin: 0 auto;">
      Instant real-time analysis of URLs, domains, IP reputation, password breaches, SSL certificates, and email headers.
    </p>
  </div>

  <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 2rem;">

    <!-- 1. URL Scanner Card -->
    <div style="background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(20px); border: 1px solid rgba(99, 102, 241, 0.25); border-radius: 20px; padding: 2.25rem; box-shadow: 0 10px 30px rgba(0,0,0,0.4); display: flex; flex-direction: column; justify-content: space-between;">
      <div>
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.25rem;">
          <div style="width: 48px; height: 48px; background: rgba(99, 102, 241, 0.15); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; border: 1px solid rgba(99, 102, 241, 0.3);">🔗</div>
          <span style="background: rgba(59, 130, 246, 0.15); color: #93c5fd; font-size: 0.75rem; font-weight: 700; padding: 4px 10px; border-radius: 9999px;">Model-dependent ML scoring</span>
        </div>
        <h3 style="font-size: 1.35rem; font-weight: 800; margin-bottom: 0.5rem;">URL Phishing Scanner</h3>
        <p style="color: #94a3b8; font-size: 0.925rem; line-height: 1.5; margin-bottom: 1.5rem;">Uses the trained XGBoost model when available; otherwise, a clearly identified heuristic fallback scores scam indicators.</p>
      </div>

      <form action="{{ route('scan') }}" method="POST">
        @csrf
        <div style="margin-bottom: 1rem;">
          <input type="text" name="url" placeholder="https://suspicious-link.com" required style="width: 100%; padding: 0.9rem 1.1rem; border-radius: 10px; border: 1px solid #33334d; background: #060814; color: #fff; font-size: 0.95rem; outline: none;">
        </div>
        <button type="submit" style="width: 100%; padding: 0.9rem; background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%); color: #fff; border: none; border-radius: 10px; font-weight: 800; font-size: 0.95rem; cursor: pointer; transition: transform 0.2s;">
          Inspect URL Threat →
        </button>
      </form>
    </div>

    <!-- 2. Domain Intelligence Card -->
    <div style="background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(20px); border: 1px solid rgba(99, 102, 241, 0.25); border-radius: 20px; padding: 2.25rem; box-shadow: 0 10px 30px rgba(0,0,0,0.4); display: flex; flex-direction: column; justify-content: space-between;">
      <div>
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.25rem;">
          <div style="width: 48px; height: 48px; background: rgba(217, 70, 239, 0.15); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; border: 1px solid rgba(217, 70, 239, 0.3);">🌐</div>
          <span style="background: rgba(59, 130, 246, 0.15); color: #3b82f6; font-size: 0.75rem; font-weight: 700; padding: 4px 10px; border-radius: 9999px;">DNS & WHOIS</span>
        </div>
        <h3 style="font-size: 1.35rem; font-weight: 800; margin-bottom: 0.5rem;">Domain Intelligence</h3>
        <p style="color: #94a3b8; font-size: 0.925rem; line-height: 1.5; margin-bottom: 1.5rem;">Fetch host IP mapping, A/MX/NS/TXT records, and domain registrar WHOIS data.</p>
      </div>

      <form action="{{ route('tools.lookup-domain') }}" method="POST">
        @csrf
        <div style="margin-bottom: 1rem;">
          <input type="text" name="domain" placeholder="example-domain.org" required style="width: 100%; padding: 0.9rem 1.1rem; border-radius: 10px; border: 1px solid #33334d; background: #060814; color: #fff; font-size: 0.95rem; outline: none;">
        </div>
        <button type="submit" style="width: 100%; padding: 0.9rem; background: linear-gradient(135deg, #d946ef 0%, #a855f7 100%); color: #fff; border: none; border-radius: 10px; font-weight: 800; font-size: 0.95rem; cursor: pointer; transition: transform 0.2s;">
          Lookup Domain Details →
        </button>
      </form>
    </div>

    <!-- 3. IP Reputation Card -->
    <div style="background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(20px); border: 1px solid rgba(99, 102, 241, 0.25); border-radius: 20px; padding: 2.25rem; box-shadow: 0 10px 30px rgba(0,0,0,0.4); display: flex; flex-direction: column; justify-content: space-between;">
      <div>
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.25rem;">
          <div style="width: 48px; height: 48px; background: rgba(16, 185, 129, 0.15); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; border: 1px solid rgba(16, 185, 129, 0.3);">📍</div>
          <span style="background: rgba(16, 185, 129, 0.15); color: #10b981; font-size: 0.75rem; font-weight: 700; padding: 4px 10px; border-radius: 9999px;">GeoIP Active</span>
        </div>
        <h3 style="font-size: 1.35rem; font-weight: 800; margin-bottom: 0.5rem;">IP Geolocation & Abuse</h3>
        <p style="color: #94a3b8; font-size: 0.925rem; line-height: 1.5; margin-bottom: 1.5rem;">Pinpoint host country, ISP organization, proxy indicators, and spam risk scores.</p>
      </div>

      <form action="{{ route('tools.lookup-ip') }}" method="POST">
        @csrf
        <div style="margin-bottom: 1rem;">
          <input type="text" name="ip" placeholder="e.g. 8.8.8.8" required style="width: 100%; padding: 0.9rem 1.1rem; border-radius: 10px; border: 1px solid #33334d; background: #060814; color: #fff; font-size: 0.95rem; outline: none;">
        </div>
        <button type="submit" style="width: 100%; padding: 0.9rem; background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: #fff; border: none; border-radius: 10px; font-weight: 800; font-size: 0.95rem; cursor: pointer; transition: transform 0.2s;">
          Check IP Reputation →
        </button>
      </form>
    </div>

    <!-- 4. Password Leak Checker -->
    <div style="background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(20px); border: 1px solid rgba(99, 102, 241, 0.25); border-radius: 20px; padding: 2.25rem; box-shadow: 0 10px 30px rgba(0,0,0,0.4); display: flex; flex-direction: column; justify-content: space-between;">
      <div>
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.25rem;">
          <div style="width: 48px; height: 48px; background: rgba(245, 158, 11, 0.15); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; border: 1px solid rgba(245, 158, 11, 0.3);">🔐</div>
          <span style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; font-size: 0.75rem; font-weight: 700; padding: 4px 10px; border-radius: 9999px;">k-Anonymity SHA-1</span>
        </div>
        <h3 style="font-size: 1.35rem; font-weight: 800; margin-bottom: 0.5rem;">Password Breach Inspector</h3>
        <p style="color: #94a3b8; font-size: 0.925rem; line-height: 1.5; margin-bottom: 1.5rem;">Safely check if a password has appeared in known dark web data breaches without revealing it.</p>
      </div>

      <form action="{{ route('tools.check-password') }}" method="POST">
        @csrf
        <div style="margin-bottom: 1rem;">
          <input type="password" name="password" placeholder="Enter password to check..." required style="width: 100%; padding: 0.9rem 1.1rem; border-radius: 10px; border: 1px solid #33334d; background: #060814; color: #fff; font-size: 0.95rem; outline: none;">
        </div>
        <button type="submit" style="width: 100%; padding: 0.9rem; background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); color: #fff; border: none; border-radius: 10px; font-weight: 800; font-size: 0.95rem; cursor: pointer; transition: transform 0.2s;">
          Check Password Security →
        </button>
      </form>
    </div>

    <!-- 5. SSL Certificate Inspector -->
    <div style="background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(20px); border: 1px solid rgba(99, 102, 241, 0.25); border-radius: 20px; padding: 2.25rem; box-shadow: 0 10px 30px rgba(0,0,0,0.4); display: flex; flex-direction: column; justify-content: space-between;">
      <div>
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.25rem;">
          <div style="width: 48px; height: 48px; background: rgba(59, 130, 246, 0.15); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; border: 1px solid rgba(59, 130, 246, 0.3);">🔒</div>
          <span style="background: rgba(59, 130, 246, 0.15); color: #3b82f6; font-size: 0.75rem; font-weight: 700; padding: 4px 10px; border-radius: 9999px;">TLS 1.3 / X.509</span>
        </div>
        <h3 style="font-size: 1.35rem; font-weight: 800; margin-bottom: 0.5rem;">SSL/TLS Certificate Checker</h3>
        <p style="color: #94a3b8; font-size: 0.925rem; line-height: 1.5; margin-bottom: 1.5rem;">Verify SSL issuer, protocol support, chain integrity, and exact expiration days.</p>
      </div>

      <form action="{{ route('tools.check-ssl') }}" method="POST">
        @csrf
        <div style="margin-bottom: 1rem;">
          <input type="text" name="domain" placeholder="example-site.com" required style="width: 100%; padding: 0.9rem 1.1rem; border-radius: 10px; border: 1px solid #33334d; background: #060814; color: #fff; font-size: 0.95rem; outline: none;">
        </div>
        <button type="submit" style="width: 100%; padding: 0.9rem; background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%); color: #fff; border: none; border-radius: 10px; font-weight: 800; font-size: 0.95rem; cursor: pointer; transition: transform 0.2s;">
          Inspect SSL Certificate →
        </button>
      </form>
    </div>

    <!-- 6. Scam Intent AI Text Analyzer -->
    <div style="background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(20px); border: 1px solid rgba(99, 102, 241, 0.25); border-radius: 20px; padding: 2.25rem; box-shadow: 0 10px 30px rgba(0,0,0,0.4); display: flex; flex-direction: column; justify-content: space-between;">
      <div>
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.25rem;">
          <div style="width: 48px; height: 48px; background: rgba(239, 68, 68, 0.15); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; border: 1px solid rgba(239, 68, 68, 0.3);">💬</div>
          <span style="background: rgba(239, 68, 68, 0.15); color: #ef4444; font-size: 0.75rem; font-weight: 700; padding: 4px 10px; border-radius: 9999px;">Gemini Fraud Analysis</span>
        </div>
        <h3 style="font-size: 1.35rem; font-weight: 800; margin-bottom: 0.5rem;">SMS & Message Scam Detector</h3>
        <p style="color: #94a3b8; font-size: 0.925rem; line-height: 1.5; margin-bottom: 1.5rem;">Paste suspicious SMS messages, WhatsApp text, or emails to analyze fraud patterns.</p>
      </div>

      <form action="{{ route('ai.scam') }}" method="POST">
        @csrf
        <div style="margin-bottom: 1rem;">
          <input type="text" name="text" placeholder="Paste SMS/Email text..." required style="width: 100%; padding: 0.9rem 1.1rem; border-radius: 10px; border: 1px solid #33334d; background: #060814; color: #fff; font-size: 0.95rem; outline: none;">
        </div>
        <button type="submit" style="width: 100%; padding: 0.9rem; background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); color: #fff; border: none; border-radius: 10px; font-weight: 800; font-size: 0.95rem; cursor: pointer; transition: transform 0.2s;">
          Analyze Scam Text →
        </button>
      </form>
    </div>

    <!-- 7. Security Headers -->
    <div style="background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(20px); border: 1px solid rgba(99, 102, 241, 0.25); border-radius: 20px; padding: 2.25rem; box-shadow: 0 10px 30px rgba(0,0,0,0.4); display: flex; flex-direction: column; justify-content: space-between;">
      <div>
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.25rem;">
          <div style="width: 48px; height: 48px; background: rgba(59, 130, 246, 0.15); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; border: 1px solid rgba(59, 130, 246, 0.3);">🛡️</div>
          <span style="background: rgba(59, 130, 246, 0.15); color: #3b82f6; font-size: 0.75rem; font-weight: 700; padding: 4px 10px; border-radius: 9999px;">HTTP Security</span>
        </div>
        <h3 style="font-size: 1.35rem; font-weight: 800; margin-bottom: 0.5rem;">Security Headers Inspector</h3>
        <p style="color: #94a3b8; font-size: 0.925rem; line-height: 1.5; margin-bottom: 1.5rem;">Check for missing HSTS, CSP, and X-Frame-Options headers.</p>
      </div>

      <form action="{{ url('api/v1/headers/check') }}" method="POST">
        @csrf
        <div style="margin-bottom: 1rem;">
          <input type="text" name="url" placeholder="https://example.com" required style="width: 100%; padding: 0.9rem 1.1rem; border-radius: 10px; border: 1px solid #33334d; background: #060814; color: #fff; font-size: 0.95rem; outline: none;">
        </div>
        <button type="submit" style="width: 100%; padding: 0.9rem; background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%); color: #fff; border: none; border-radius: 10px; font-weight: 800; font-size: 0.95rem; cursor: pointer; transition: transform 0.2s;">
          Inspect Headers →
        </button>
      </form>
    </div>

    <!-- 8. Redirect Tracer -->
    <div style="background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(20px); border: 1px solid rgba(99, 102, 241, 0.25); border-radius: 20px; padding: 2.25rem; box-shadow: 0 10px 30px rgba(0,0,0,0.4); display: flex; flex-direction: column; justify-content: space-between;">
      <div>
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.25rem;">
          <div style="width: 48px; height: 48px; background: rgba(245, 158, 11, 0.15); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; border: 1px solid rgba(245, 158, 11, 0.3);">🔄</div>
          <span style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; font-size: 0.75rem; font-weight: 700; padding: 4px 10px; border-radius: 9999px;">Hop Analysis</span>
        </div>
        <h3 style="font-size: 1.35rem; font-weight: 800; margin-bottom: 0.5rem;">URL Redirect Tracer</h3>
        <p style="color: #94a3b8; font-size: 0.925rem; line-height: 1.5; margin-bottom: 1.5rem;">Unmask shortened links and trace HTTP redirect chains to find hidden destinations.</p>
      </div>

      <form action="{{ url('api/v1/redirects/check') }}" method="POST">
        @csrf
        <div style="margin-bottom: 1rem;">
          <input type="text" name="url" placeholder="http://bit.ly/xyz" required style="width: 100%; padding: 0.9rem 1.1rem; border-radius: 10px; border: 1px solid #33334d; background: #060814; color: #fff; font-size: 0.95rem; outline: none;">
        </div>
        <button type="submit" style="width: 100%; padding: 0.9rem; background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); color: #fff; border: none; border-radius: 10px; font-weight: 800; font-size: 0.95rem; cursor: pointer; transition: transform 0.2s;">
          Trace Redirects →
        </button>
      </form>
    </div>

    <!-- 9. Phone Number Risk -->
    <div style="background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(20px); border: 1px solid rgba(99, 102, 241, 0.25); border-radius: 20px; padding: 2.25rem; box-shadow: 0 10px 30px rgba(0,0,0,0.4); display: flex; flex-direction: column; justify-content: space-between;">
      <div>
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.25rem;">
          <div style="width: 48px; height: 48px; background: rgba(16, 185, 129, 0.15); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; border: 1px solid rgba(16, 185, 129, 0.3);">📞</div>
          <span style="background: rgba(16, 185, 129, 0.15); color: #10b981; font-size: 0.75rem; font-weight: 700; padding: 4px 10px; border-radius: 9999px;">Telecom Risk</span>
        </div>
        <h3 style="font-size: 1.35rem; font-weight: 800; margin-bottom: 0.5rem;">Phone Number Checker</h3>
        <p style="color: #94a3b8; font-size: 0.925rem; line-height: 1.5; margin-bottom: 1.5rem;">Check if a number is toll-free, premium, or commonly used in tech support scams.</p>
      </div>

      <form action="{{ url('api/v1/phone/check') }}" method="POST">
        @csrf
        <div style="margin-bottom: 1rem;">
          <input type="text" name="phone" placeholder="+1 800 123 4567" required style="width: 100%; padding: 0.9rem 1.1rem; border-radius: 10px; border: 1px solid #33334d; background: #060814; color: #fff; font-size: 0.95rem; outline: none;">
        </div>
        <button type="submit" style="width: 100%; padding: 0.9rem; background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: #fff; border: none; border-radius: 10px; font-weight: 800; font-size: 0.95rem; cursor: pointer; transition: transform 0.2s;">
          Check Number Risk →
        </button>
      </form>
    </div>

    <!-- 10. Social Media Scam Analyzer -->
    <div style="background: rgba(15, 23, 42, 0.7); backdrop-filter: blur(20px); border: 1px solid rgba(99, 102, 241, 0.25); border-radius: 20px; padding: 2.25rem; box-shadow: 0 10px 30px rgba(0,0,0,0.4); display: flex; flex-direction: column; justify-content: space-between;">
      <div>
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.25rem;">
          <div style="width: 48px; height: 48px; background: rgba(217, 70, 239, 0.15); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.5rem; border: 1px solid rgba(217, 70, 239, 0.3);">📱</div>
          <span style="background: rgba(217, 70, 239, 0.15); color: #d946ef; font-size: 0.75rem; font-weight: 700; padding: 4px 10px; border-radius: 9999px;">Impersonation Detection</span>
        </div>
        <h3 style="font-size: 1.35rem; font-weight: 800; margin-bottom: 0.5rem;">Social Profile Scam Check</h3>
        <p style="color: #94a3b8; font-size: 0.925rem; line-height: 1.5; margin-bottom: 1.5rem;">Analyze social handles for brand typosquatting or common giveaway scam patterns.</p>
      </div>

      <form action="{{ url('api/v1/social/check') }}" method="POST">
        @csrf
        <div style="margin-bottom: 1rem;">
          <input type="text" name="input" placeholder="twitter.com/official_support" required style="width: 100%; padding: 0.9rem 1.1rem; border-radius: 10px; border: 1px solid #33334d; background: #060814; color: #fff; font-size: 0.95rem; outline: none;">
        </div>
        <button type="submit" style="width: 100%; padding: 0.9rem; background: linear-gradient(135deg, #d946ef 0%, #a855f7 100%); color: #fff; border: none; border-radius: 10px; font-weight: 800; font-size: 0.95rem; cursor: pointer; transition: transform 0.2s;">
          Analyze Profile →
        </button>
      </form>
    </div>
</section>
@endsection
