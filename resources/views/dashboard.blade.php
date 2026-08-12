@extends('layouts.app')

@section('title', 'Dashboard — Block Bord AI')

@section('content')
<div style="display: flex; min-height: calc(100vh - 70px);">
  <x-sidebar />

  <main style="flex: 1; padding: 2.5rem; background: #0f0f17;">
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem;">
      <div>
        <h1 style="font-size: 2rem; font-weight: 800; color: #fff;">Welcome back, {{ $user->username }} 👋</h1>
        <p style="color: #94a3b8; font-size: 0.95rem;">Plan: <span style="text-transform: uppercase; font-weight: 700; color: #818cf8;">{{ $user->plan }}</span></p>
      </div>
      <a href="{{ route('tools.home') }}" style="background: #6366f1; color: #fff; padding: 0.75rem 1.5rem; border-radius: 8px; font-weight: 600; text-decoration: none;">New Security Scan</a>
    </div>

    <!-- Stat Cards -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.5rem; margin-bottom: 2.5rem;">
      <div style="background: #1e1e2e; padding: 1.5rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08);">
        <div style="color: #94a3b8; font-size: 0.875rem;">Total Scans</div>
        <div style="font-size: 2rem; font-weight: 800; color: #fff; margin-top: 0.25rem;">{{ $totalScans }}</div>
      </div>
      <div style="background: #1e1e2e; padding: 1.5rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08);">
        <div style="color: #94a3b8; font-size: 0.875rem;">Threats Blocked</div>
        <div style="font-size: 2rem; font-weight: 800; color: #ef4444; margin-top: 0.25rem;">{{ $threatsBlocked }}</div>
      </div>
      <div style="background: #1e1e2e; padding: 1.5rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08);">
        <div style="color: #94a3b8; font-size: 0.875rem;">API Key</div>
        <div style="font-size: 0.875rem; font-weight: 600; color: #10b981; margin-top: 0.5rem; font-family: monospace;">
          {{ $user->api_key ? substr($user->api_key, 0, 12) . '...' : 'None Generated' }}
        </div>
      </div>
    </div>

    <!-- Recent Scans Table -->
    <div style="background: #1e1e2e; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08); padding: 1.5rem;">
      <h3 style="color: #fff; font-size: 1.25rem; font-weight: 700; margin-bottom: 1rem;">Recent Scans</h3>
      @if($recentScans->isEmpty())
        <p style="color: #94a3b8;">No scans performed yet. <a href="{{ route('tools.home') }}" style="color: #818cf8;">Scan your first link</a>.</p>
      @else
        <table style="width: 100%; border-collapse: collapse; text-align: left; color: #cbd5e1;">
          <thead>
            <tr style="border-bottom: 1px solid #33334d; color: #94a3b8;">
              <th style="padding: 0.75rem;">Target</th>
              <th style="padding: 0.75rem;">Risk Level</th>
              <th style="padding: 0.75rem;">Score</th>
              <th style="padding: 0.75rem;">Date</th>
            </tr>
          </thead>
          <tbody>
            @foreach($recentScans as $scan)
              <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                <td style="padding: 0.75rem; word-break: break-all;">{{ $scan->content }}</td>
                <td style="padding: 0.75rem;">
                  <span style="padding: 0.25rem 0.65rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; background: {{ $scan->risk_level === 'high' ? '#ef4444' : ($scan->risk_level === 'medium' ? '#f59e0b' : '#10b981') }}; color: white;">
                    {{ $scan->risk_level }}
                  </span>
                </td>
                <td style="padding: 0.75rem;">{{ $scan->risk_score }}/100</td>
                <td style="padding: 0.75rem;">{{ $scan->created_at->diffForHumans() }}</td>
              </tr>
            @endforeach
          </tbody>
        </table>
      @endif
    </div>
  </main>
</div>
@endsection
