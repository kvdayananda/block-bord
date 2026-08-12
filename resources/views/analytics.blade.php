@extends('layouts.app')
@section('title', 'Analytics — Block Bord AI')
@section('content')
<div style="display: flex; min-height: calc(100vh - 70px);">
  <x-sidebar />
  <main style="flex: 1; padding: 2.5rem; background: #0f0f17; color: #fff;">
    <h1 style="font-size: 2rem; font-weight: 800; margin-bottom: 1.5rem;">Security Analytics</h1>
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem;">
      <div style="background: #1e1e2e; padding: 1.5rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08);">
        <div style="color: #94a3b8;">Total Scans</div>
        <div style="font-size: 2rem; font-weight: 800; color: #6366f1;">{{ $totalScans }}</div>
      </div>
      <div style="background: #1e1e2e; padding: 1.5rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08);">
        <div style="color: #94a3b8;">Safe Links</div>
        <div style="font-size: 2rem; font-weight: 800; color: #10b981;">{{ $safeCount }}</div>
      </div>
      <div style="background: #1e1e2e; padding: 1.5rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08);">
        <div style="color: #94a3b8;">Suspicious (Medium)</div>
        <div style="font-size: 2rem; font-weight: 800; color: #f59e0b;">{{ $mediumCount }}</div>
      </div>
      <div style="background: #1e1e2e; padding: 1.5rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08);">
        <div style="color: #94a3b8;">Malicious (High)</div>
        <div style="font-size: 2rem; font-weight: 800; color: #ef4444;">{{ $highCount }}</div>
      </div>
    </div>
  </main>
</div>
@endsection
