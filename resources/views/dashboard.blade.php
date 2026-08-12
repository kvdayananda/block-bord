@extends('layouts.app')

@section('title', 'Security Command Center — Block Bord AI')

@section('content')
<div style="display: flex; min-height: calc(100vh - 70px); background: #060814;">
  <x-sidebar />

  <main style="flex: 1; padding: 2.5rem; background: #060814; color: #fff;">
    
    <!-- User Welcome Header -->
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2.5rem; flex-wrap: wrap; gap: 1rem;">
      <div>
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 6px;">
          <h1 style="font-size: 2.25rem; font-weight: 900; color: #fff; margin: 0;">Command Center</h1>
          <span style="background: rgba(99, 102, 241, 0.2); color: #a5b4fc; font-weight: 700; padding: 4px 12px; border-radius: 9999px; font-size: 0.75rem; border: 1px solid rgba(99,102,241,0.3); text-transform: uppercase;">
            {{ $user->plan }} Plan
          </span>
        </div>
        <p style="color: #94a3b8; font-size: 0.975rem;">Welcome back, <strong>{{ $user->username }}</strong> — Real-Time Shield Active</p>
      </div>

      <div style="display: flex; gap: 12px;">
        <a href="{{ route('tools.home') }}" style="background: linear-gradient(135deg, #6366f1 0%, #d946ef 100%); color: #fff; padding: 0.85rem 1.6rem; border-radius: 12px; font-weight: 800; font-size: 0.925rem; text-decoration: none; box-shadow: 0 4px 20px rgba(99, 102, 241, 0.35); transition: transform 0.2s;">
          ⚡ Launch Security Scan
        </a>
      </div>
    </div>

    <!-- Stat Metric Cards Grid -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 1.5rem; margin-bottom: 3rem;">
      
      <!-- Total Scans -->
      <div style="background: rgba(15, 23, 42, 0.75); backdrop-filter: blur(16px); border: 1px solid rgba(99, 102, 241, 0.2); border-radius: 18px; padding: 1.75rem; box-shadow: 0 8px 24px rgba(0,0,0,0.4);">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
          <span style="color: #94a3b8; font-size: 0.875rem; font-weight: 600;">Total Analyzed</span>
          <span style="font-size: 1.25rem;">🔍</span>
        </div>
        <div style="font-size: 2.25rem; font-weight: 900; color: #fff;">{{ $totalScans }}</div>
        <div style="font-size: 0.8rem; color: #10b981; margin-top: 6px; font-weight: 600;">↑ 100% Heuristic Engine</div>
      </div>

      <!-- Threats Blocked -->
      <div style="background: rgba(15, 23, 42, 0.75); backdrop-filter: blur(16px); border: 1px solid rgba(239, 68, 68, 0.25); border-radius: 18px; padding: 1.75rem; box-shadow: 0 8px 24px rgba(0,0,0,0.4);">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
          <span style="color: #94a3b8; font-size: 0.875rem; font-weight: 600;">Threats Neutralized</span>
          <span style="font-size: 1.25rem;">🛡️</span>
        </div>
        <div style="font-size: 2.25rem; font-weight: 900; color: #ef4444;">{{ $threatsBlocked }}</div>
        <div style="font-size: 0.8rem; color: #ef4444; margin-top: 6px; font-weight: 600;">High Risk Flagged</div>
      </div>

      <!-- API Entitlement Key -->
      <div style="background: rgba(15, 23, 42, 0.75); backdrop-filter: blur(16px); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 18px; padding: 1.75rem; box-shadow: 0 8px 24px rgba(0,0,0,0.4);">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
          <span style="color: #94a3b8; font-size: 0.875rem; font-weight: 600;">Active API Key</span>
          <span style="font-size: 1.25rem;">🔑</span>
        </div>
        <div style="font-size: 0.95rem; font-weight: 700; color: #10b981; font-family: var(--font-mono, monospace); margin-top: 4px; word-break: break-all;">
          {{ $user->api_key ? substr($user->api_key, 0, 14) . '...' : 'Key Not Issued' }}
        </div>
        <a href="{{ route('settings') }}" style="display: inline-block; font-size: 0.8rem; color: #818cf8; margin-top: 8px; font-weight: 600; text-decoration: none;">Manage API Access →</a>
      </div>

      <!-- Overall Protection Status -->
      <div style="background: rgba(15, 23, 42, 0.75); backdrop-filter: blur(16px); border: 1px solid rgba(99, 102, 241, 0.2); border-radius: 18px; padding: 1.75rem; box-shadow: 0 8px 24px rgba(0,0,0,0.4);">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
          <span style="color: #94a3b8; font-size: 0.875rem; font-weight: 600;">Shield Score</span>
          <span style="font-size: 1.25rem;">⚡</span>
        </div>
        <div style="font-size: 2.25rem; font-weight: 900; color: #10b981;">98 / 100</div>
        <div style="font-size: 0.8rem; color: #10b981; margin-top: 6px; font-weight: 600;">Optimal Security Rating</div>
      </div>

    </div>

    <!-- Recent Scans Data Table -->
    <div style="background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(20px); border-radius: 20px; border: 1px solid rgba(99, 102, 241, 0.2); padding: 2rem; box-shadow: 0 12px 32px rgba(0,0,0,0.5);">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
        <h3 style="color: #fff; font-size: 1.35rem; font-weight: 800; margin: 0;">Recent Threat Intelligence Scans</h3>
        <a href="{{ route('history') }}" style="color: #a5b4fc; font-size: 0.9rem; font-weight: 700; text-decoration: none;">View Full History →</a>
      </div>

      @if($recentScans->isEmpty())
        <div style="text-align: center; padding: 3rem 1rem; color: #94a3b8;">
          <div style="font-size: 2.5rem; margin-bottom: 1rem;">🔍</div>
          <p style="font-size: 1.1rem; margin-bottom: 1rem;">No scans performed yet.</p>
          <a href="{{ route('tools.home') }}" style="display: inline-block; background: #6366f1; color: #fff; padding: 0.75rem 1.5rem; border-radius: 10px; font-weight: 700; text-decoration: none;">Scan First Link</a>
        </div>
      @else
        <div style="overflow-x: auto;">
          <table style="width: 100%; border-collapse: collapse; text-align: left; color: #cbd5e1;">
            <thead>
              <tr style="border-bottom: 1px solid rgba(99, 102, 241, 0.2); color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em;">
                <th style="padding: 1rem;">Target Content</th>
                <th style="padding: 1rem;">Classification</th>
                <th style="padding: 1rem;">Risk Score</th>
                <th style="padding: 1rem;">Timestamp</th>
              </tr>
            </thead>
            <tbody>
              @foreach($recentScans as $scan)
                <tr style="border-bottom: 1px solid rgba(255,255,255,0.05); transition: background 0.2s;" onmouseover="this.style.background='rgba(99,102,241,0.08)'" onmouseout="this.style.background='transparent'">
                  <td style="padding: 1rem; font-weight: 600; color: #fff; word-break: break-all;">{{ $scan->content }}</td>
                  <td style="padding: 1rem;">
                    <span style="padding: 0.35rem 0.85rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.04em; background: {{ $scan->risk_level === 'high' ? 'rgba(239, 68, 68, 0.2)' : ($scan->risk_level === 'medium' ? 'rgba(245, 158, 11, 0.2)' : 'rgba(16, 185, 129, 0.2)') }}; color: {{ $scan->risk_level === 'high' ? '#ef4444' : ($scan->risk_level === 'medium' ? '#f59e0b' : '#10b981') }}; border: 1px solid {{ $scan->risk_level === 'high' ? 'rgba(239, 68, 68, 0.4)' : ($scan->risk_level === 'medium' ? 'rgba(245, 158, 11, 0.4)' : 'rgba(16, 185, 129, 0.4)') }};">
                      {{ $scan->risk_level }}
                    </span>
                  </td>
                  <td style="padding: 1rem; font-weight: 700; color: #a5b4fc;">{{ $scan->risk_score }} / 100</td>
                  <td style="padding: 1rem; color: #94a3b8; font-size: 0.875rem;">{{ $scan->created_at->diffForHumans() }}</td>
                </tr>
              @endforeach
            </tbody>
          </table>
        </div>
      @endif
    </div>

  </main>
</div>
@endsection
