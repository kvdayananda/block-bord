@extends('layouts.app')
@section('title', 'Scan Analysis Detail — Block Bord AI')
@section('content')
<section style="padding: 4rem 1.5rem; max-width: 800px; margin: 0 auto; color: #fff;">
  <h1 style="font-size: 2rem; font-weight: 800; margin-bottom: 1.5rem;">Threat Analysis Report</h1>

  <div style="background: #1e1e2e; padding: 2rem; border-radius: 14px; border: 1px solid rgba(255,255,255,0.08);">
    <div style="margin-bottom: 1.5rem;">
      <span style="color: #94a3b8; font-size: 0.9rem;">Target Analyzed</span>
      <div style="font-size: 1.25rem; font-weight: 700; color: #818cf8; word-break: break-all;">{{ $scan['url'] ?? $scan['content'] ?? 'N/A' }}</div>
    </div>

    <div style="display: flex; gap: 2rem; margin-bottom: 2rem;">
      <div>
        <span style="color: #94a3b8; font-size: 0.9rem;">Risk Score</span>
        <div style="font-size: 2.5rem; font-weight: 900; color: {{ ($scan['risk_score'] ?? 0) >= 70 ? '#ef4444' : (($scan['risk_score'] ?? 0) >= 35 ? '#f59e0b' : '#10b981') }};">
          {{ $scan['risk_score'] ?? 0 }}/100
        </div>
      </div>
      <div>
        <span style="color: #94a3b8; font-size: 0.9rem;">Classification</span>
        <div style="font-size: 1.5rem; font-weight: 800; text-transform: uppercase; margin-top: 0.5rem;">
          {{ $scan['risk_level'] ?? 'UNKNOWN' }}
        </div>
      </div>
    </div>

    <h3 style="font-size: 1.1rem; font-weight: 700; margin-bottom: 0.75rem;">Detected Indicators & Heuristics</h3>
    <ul style="color: #cbd5e1; line-height: 1.8;">
      @if(!empty($scan['reasons']))
        @foreach($scan['reasons'] as $reason)
          <li>⚠️ {{ $reason }}</li>
        @endforeach
      @else
        <li>✅ No malicious flags detected.</li>
      @endif
    </ul>
  </div>
</section>
@endsection
