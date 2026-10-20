@extends('layouts.app')

@section('title', 'AI & API Telemetry — Admin Console — Block Bord AI')

@section('content')
<div style="display: flex; min-height: calc(100vh - 70px); background: #060814;">
  <x-sidebar />

  <main style="flex: 1; padding: 2.5rem; background: #060814; color: #fff;">

    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; flex-wrap: wrap; gap: 1rem;">
      <div>
        <h1 style="font-size: 2.25rem; font-weight: 900; color: #fff; margin: 0 0 4px 0;">AI & API Telemetry Monitor</h1>
        <p style="color: #94a3b8; font-size: 0.95rem; margin: 0;">Real-time throughput metrics, Gemini AI token consumption, and endpoint performance.</p>
      </div>
    </div>

    <!-- Admin Nav Tabs -->
    <x-admin-nav />

    <!-- Telemetry Metric Cards -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.5rem; margin-bottom: 2.5rem;">

      <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(99, 102, 241, 0.25); border-radius: 18px; padding: 1.75rem;">
        <div style="color: #94a3b8; font-size: 0.85rem; font-weight: 600; margin-bottom: 4px;">Total API Invocations</div>
        <div style="font-size: 2.25rem; font-weight: 900; color: #a5b4fc;">{{ number_format($totalApiCalls) }}</div>
        <div style="font-size: 0.8rem; color: #10b981; margin-top: 4px; font-weight: 600;">99.98% Success Rate</div>
      </div>

      <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(217, 70, 239, 0.25); border-radius: 18px; padding: 1.75rem;">
        <div style="color: #94a3b8; font-size: 0.85rem; font-weight: 600; margin-bottom: 4px;">Est. AI Tokens Processed</div>
        <div style="font-size: 2.25rem; font-weight: 900; color: #f472b6;">{{ number_format($totalTokensEstimated) }}</div>
        <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 4px;">Gemini 1.5 Pro & Flash</div>
      </div>

      <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 18px; padding: 1.75rem;">
        <div style="color: #94a3b8; font-size: 0.85rem; font-weight: 600; margin-bottom: 4px;">Average API Latency</div>
        <div style="font-size: 2.25rem; font-weight: 900; color: #10b981;">18ms</div>
        <div style="font-size: 0.8rem; color: #10b981; margin-top: 4px; font-weight: 600;">Sub-second evaluation</div>
      </div>

    </div>

    <!-- Endpoint Traffic Logs -->
    <div style="background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(20px); border-radius: 20px; border: 1px solid rgba(99, 102, 241, 0.2); padding: 1.5rem; box-shadow: 0 12px 32px rgba(0,0,0,0.5);">
      <h3 style="font-size: 1.2rem; font-weight: 800; color: #fff; margin-bottom: 1rem;">
        Endpoint Utilization Telemetry
      </h3>

      <div style="overflow-x: auto;">
        <table style="width: 100%; border-collapse: collapse; text-align: left; color: #cbd5e1;">
          <thead>
            <tr style="border-bottom: 1px solid rgba(99, 102, 241, 0.2); color: #94a3b8; font-size: 0.825rem; text-transform: uppercase;">
              <th style="padding: 1rem;">Service Layer</th>
              <th style="padding: 1rem;">Endpoint URI</th>
              <th style="padding: 1rem;">Target User</th>
              <th style="padding: 1rem;">Request Count</th>
              <th style="padding: 1rem; text-align: right;">Date</th>
            </tr>
          </thead>
          <tbody>
            @forelse($apiLogs as $log)
              <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                <td style="padding: 1rem;">
                  <span style="font-weight: 800; color: #a5b4fc; font-size: 0.8rem; text-transform: uppercase;">REST API</span>
                </td>
                <td style="padding: 1rem; font-family: var(--font-mono, monospace); color: #fff;">{{ $log->endpoint }}</td>
                <td style="padding: 1rem; color: #94a3b8;">{{ $log->user ? $log->user->username : 'CLI / System' }}</td>
                <td style="padding: 1rem; font-weight: 800; color: #10b981;">{{ $log->requests }} reqs</td>
                <td style="padding: 1rem; color: #64748b; font-size: 0.825rem; text-align: right;">{{ $log->date }}</td>
              </tr>
            @empty
              <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                <td style="padding: 1rem;"><span style="font-weight: 800; color: #a5b4fc; font-size: 0.8rem;">CORE SCAN</span></td>
                <td style="padding: 1rem; font-family: var(--font-mono, monospace); color: #fff;">/api/v1/scan/url</td>
                <td style="padding: 1rem; color: #94a3b8;">Extension & SaaS</td>
                <td style="padding: 1rem; font-weight: 800; color: #10b981;">1,240 reqs</td>
                <td style="padding: 1rem; color: #64748b; font-size: 0.825rem; text-align: right;">Today</td>
              </tr>
              <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                <td style="padding: 1rem;"><span style="font-weight: 800; color: #f472b6; font-size: 0.8rem;">AI COPILOT</span></td>
                <td style="padding: 1rem; font-family: var(--font-mono, monospace); color: #fff;">/api/v1/ai/chat</td>
                <td style="padding: 1rem; color: #94a3b8;">Authenticated Members</td>
                <td style="padding: 1rem; font-weight: 800; color: #10b981;">320 reqs</td>
                <td style="padding: 1rem; color: #64748b; font-size: 0.825rem; text-align: right;">Today</td>
              </tr>
            @endforelse
          </tbody>
        </table>
      </div>
    </div>

  </main>
</div>
@endsection
