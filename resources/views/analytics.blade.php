@extends('layouts.app')

@section('title', 'Security Analytics — Block Bord AI')

@section('content')
<div style="display: flex; min-height: calc(100vh - 70px); background: #060814;">
  <x-sidebar />

  <main style="flex: 1; padding: 2.5rem; background: #060814; color: #fff;">
    
    <div style="margin-bottom: 2.5rem;">
      <h1 style="font-size: 2.25rem; font-weight: 900; color: #fff; margin-bottom: 0.5rem;">Threat Intelligence Analytics</h1>
      <p style="color: #94a3b8; font-size: 1rem;">Visual breakdown of scanned content, threat severity ratios, and risk mitigation scores.</p>
    </div>

    <!-- Analytics Stat Cards Grid -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.5rem; margin-bottom: 3rem;">
      
      <div style="background: rgba(15, 23, 42, 0.75); backdrop-filter: blur(16px); border: 1px solid rgba(99, 102, 241, 0.25); border-radius: 18px; padding: 1.75rem; box-shadow: 0 8px 24px rgba(0,0,0,0.4);">
        <div style="color: #94a3b8; font-size: 0.875rem; font-weight: 600;">Total Analyzed Requests</div>
        <div style="font-size: 2.5rem; font-weight: 900; color: #6366f1; margin-top: 4px;">{{ $totalScans }}</div>
      </div>

      <div style="background: rgba(15, 23, 42, 0.75); backdrop-filter: blur(16px); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 18px; padding: 1.75rem; box-shadow: 0 8px 24px rgba(0,0,0,0.4);">
        <div style="color: #94a3b8; font-size: 0.875rem; font-weight: 600;">Safe Verified Links</div>
        <div style="font-size: 2.5rem; font-weight: 900; color: #10b981; margin-top: 4px;">{{ $safeCount }}</div>
      </div>

      <div style="background: rgba(15, 23, 42, 0.75); backdrop-filter: blur(16px); border: 1px solid rgba(245, 158, 11, 0.25); border-radius: 18px; padding: 1.75rem; box-shadow: 0 8px 24px rgba(0,0,0,0.4);">
        <div style="color: #94a3b8; font-size: 0.875rem; font-weight: 600;">Suspicious (Medium Risk)</div>
        <div style="font-size: 2.5rem; font-weight: 900; color: #f59e0b; margin-top: 4px;">{{ $mediumCount }}</div>
      </div>

      <div style="background: rgba(15, 23, 42, 0.75); backdrop-filter: blur(16px); border: 1px solid rgba(239, 68, 68, 0.25); border-radius: 18px; padding: 1.75rem; box-shadow: 0 8px 24px rgba(0,0,0,0.4);">
        <div style="color: #94a3b8; font-size: 0.875rem; font-weight: 600;">Malicious (High Risk)</div>
        <div style="font-size: 2.5rem; font-weight: 900; color: #ef4444; margin-top: 4px;">{{ $highCount }}</div>
      </div>

    </div>

    <!-- Threat Ratios Progress Bar Card -->
    <div style="background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(20px); border-radius: 20px; border: 1px solid rgba(99, 102, 241, 0.2); padding: 2.25rem; box-shadow: 0 12px 32px rgba(0,0,0,0.5);">
      <h3 style="font-size: 1.35rem; font-weight: 800; margin-bottom: 1.5rem;">Risk Severity Distribution</h3>
      
      @php
        $total = max(1, $totalScans);
        $safePct = round(($safeCount / $total) * 100);
        $medPct = round(($mediumCount / $total) * 100);
        $highPct = round(($highCount / $total) * 100);
      @endphp

      <div style="height: 18px; width: 100%; background: #060814; border-radius: 9999px; overflow: hidden; display: flex; margin-bottom: 2rem; border: 1px solid rgba(255,255,255,0.06);">
        <div style="width: {{ $safePct }}%; background: #10b981; transition: width 0.5s ease;" title="Safe: {{ $safePct }}%"></div>
        <div style="width: {{ $medPct }}%; background: #f59e0b; transition: width 0.5s ease;" title="Medium: {{ $medPct }}%"></div>
        <div style="width: {{ $highPct }}%; background: #ef4444; transition: width 0.5s ease;" title="High: {{ $highPct }}%"></div>
      </div>

      <div style="display: flex; gap: 2rem; flex-wrap: wrap;">
        <div style="display: flex; align-items: center; gap: 10px;">
          <span style="width: 12px; height: 12px; background: #10b981; border-radius: 50%;"></span>
          <span style="color: #cbd5e1; font-weight: 600;">Safe ({{ $safePct }}%)</span>
        </div>
        <div style="display: flex; align-items: center; gap: 10px;">
          <span style="width: 12px; height: 12px; background: #f59e0b; border-radius: 50%;"></span>
          <span style="color: #cbd5e1; font-weight: 600;">Suspicious ({{ $medPct }}%)</span>
        </div>
        <div style="display: flex; align-items: center; gap: 10px;">
          <span style="width: 12px; height: 12px; background: #ef4444; border-radius: 50%;"></span>
          <span style="color: #cbd5e1; font-weight: 600;">Malicious ({{ $highPct }}%)</span>
        </div>
      </div>
    </div>

  </main>
</div>
@endsection
