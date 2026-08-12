@extends('layouts.app')

@section('title', 'Threat Inspection Report — Block Bord AI')

@section('content')
<section style="padding: 4rem 1.5rem 6rem; max-width: 900px; margin: 0 auto; color: #fff;">
  
  <div style="margin-bottom: 2rem;">
    <a href="{{ route('tools.home') }}" style="color: #a5b4fc; font-weight: 700; text-decoration: none; font-size: 0.9rem;">← Back to Security Tools</a>
    <h1 style="font-size: 2.5rem; font-weight: 900; color: #fff; margin-top: 0.75rem;">Threat Intelligence Report</h1>
  </div>

  <div style="background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(24px); border-radius: 24px; border: 1px solid rgba(99, 102, 241, 0.3); padding: 2.5rem; box-shadow: 0 20px 50px rgba(0,0,0,0.6);">
    
    <!-- Target Analysed -->
    <div style="margin-bottom: 2rem; padding-bottom: 1.5rem; border-bottom: 1px solid rgba(255,255,255,0.08);">
      <span style="color: #64748b; font-size: 0.85rem; font-weight: 700; text-transform: uppercase;">Analyzed Target URL / Link</span>
      <div style="font-size: 1.35rem; font-weight: 800; color: #a5b4fc; word-break: break-all; margin-top: 6px; font-family: var(--font-mono, monospace);">
        {{ $scan['url'] ?? $scan['content'] ?? 'N/A' }}
      </div>
    </div>

    <!-- Score & Classification Grid -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; margin-bottom: 2.5rem;">
      
      <div style="background: #060814; padding: 1.5rem; border-radius: 16px; border: 1px solid rgba(255,255,255,0.06);">
        <span style="color: #94a3b8; font-size: 0.85rem; font-weight: 600;">Composite Risk Score</span>
        <div style="font-size: 3rem; font-weight: 900; color: {{ ($scan['risk_score'] ?? 0) >= 70 ? '#ef4444' : (($scan['risk_score'] ?? 0) >= 35 ? '#f59e0b' : '#10b981') }}; margin-top: 4px;">
          {{ $scan['risk_score'] ?? 0 }} <span style="font-size: 1.25rem; color: #64748b;">/ 100</span>
        </div>
      </div>

      <div style="background: #060814; padding: 1.5rem; border-radius: 16px; border: 1px solid rgba(255,255,255,0.06);">
        <span style="color: #94a3b8; font-size: 0.85rem; font-weight: 600;">Risk Classification</span>
        <div style="margin-top: 12px;">
          <span style="padding: 0.5rem 1.25rem; border-radius: 9999px; font-size: 0.95rem; font-weight: 900; text-transform: uppercase; letter-spacing: 0.05em; background: {{ ($scan['risk_score'] ?? 0) >= 70 ? 'rgba(239, 68, 68, 0.2)' : (($scan['risk_score'] ?? 0) >= 35 ? 'rgba(245, 158, 11, 0.2)' : 'rgba(16, 185, 129, 0.2)') }}; color: {{ ($scan['risk_score'] ?? 0) >= 70 ? '#ef4444' : (($scan['risk_score'] ?? 0) >= 35 ? '#f59e0b' : '#10b981') }}; border: 1.5px solid {{ ($scan['risk_score'] ?? 0) >= 70 ? '#ef4444' : (($scan['risk_score'] ?? 0) >= 35 ? '#f59e0b' : '#10b981') }};">
            {{ $scan['risk_level'] ?? 'SAFE' }}
          </span>
        </div>
      </div>

    </div>

    <!-- Indicator Reason List -->
    <div>
      <h3 style="font-size: 1.25rem; font-weight: 800; color: #fff; margin-bottom: 1rem;">Detected Security Indicators</h3>
      
      <div style="display: flex; flex-direction: column; gap: 10px;">
        @if(!empty($scan['reasons']))
          @foreach($scan['reasons'] as $reason)
            <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3); color: #f87171; padding: 1rem 1.25rem; border-radius: 12px; font-weight: 600; font-size: 0.95rem; display: flex; align-items: center; gap: 10px;">
              <span>⚠️</span> {{ $reason }}
            </div>
          @endforeach
        @else
          <div style="background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); color: #34d399; padding: 1rem 1.25rem; border-radius: 12px; font-weight: 600; font-size: 0.95rem; display: flex; align-items: center; gap: 10px;">
            <span>✅</span> No suspicious or malicious indicators detected.
          </div>
        @endif
      </div>
    </div>

  </div>
</section>
@endsection
