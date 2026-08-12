@extends('layouts.app')

@section('title', 'Scan History Logs — Block Bord AI')

@section('content')
<div style="display: flex; min-height: calc(100vh - 70px); background: #060814;">
  <x-sidebar />

  <main style="flex: 1; padding: 2.5rem; background: #060814; color: #fff;">
    
    <div style="margin-bottom: 2.5rem;">
      <h1 style="font-size: 2.25rem; font-weight: 900; color: #fff; margin-bottom: 0.5rem;">Scan History & Logs</h1>
      <p style="color: #94a3b8; font-size: 1rem;">Complete audit log of all URLs, domains, and IP threat inspections.</p>
    </div>

    <div style="background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(20px); border-radius: 20px; border: 1px solid rgba(99, 102, 241, 0.2); padding: 2rem; box-shadow: 0 12px 32px rgba(0,0,0,0.5);">
      @if($scans->isEmpty())
        <div style="text-align: center; padding: 3rem 1rem; color: #94a3b8;">
          <p style="font-size: 1.1rem; margin-bottom: 1rem;">No scan history recorded.</p>
          <a href="{{ route('tools.home') }}" style="display: inline-block; background: #6366f1; color: #fff; padding: 0.75rem 1.5rem; border-radius: 10px; font-weight: 700; text-decoration: none;">Launch Scan</a>
        </div>
      @else
        <div style="overflow-x: auto;">
          <table style="width: 100%; border-collapse: collapse; text-align: left; color: #cbd5e1;">
            <thead>
              <tr style="border-bottom: 1px solid rgba(99, 102, 241, 0.2); color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em;">
                <th style="padding: 1rem;">Target Content</th>
                <th style="padding: 1rem;">Risk Classification</th>
                <th style="padding: 1rem;">Risk Score</th>
                <th style="padding: 1rem;">Category</th>
                <th style="padding: 1rem;">Scanned Date</th>
              </tr>
            </thead>
            <tbody>
              @foreach($scans as $scan)
                <tr style="border-bottom: 1px solid rgba(255,255,255,0.05); transition: background 0.2s;" onmouseover="this.style.background='rgba(99,102,241,0.08)'" onmouseout="this.style.background='transparent'">
                  <td style="padding: 1rem; font-weight: 600; color: #fff; word-break: break-all;">{{ $scan->content }}</td>
                  <td style="padding: 1rem;">
                    <span style="padding: 0.35rem 0.85rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.04em; background: {{ $scan->risk_level === 'high' ? 'rgba(239, 68, 68, 0.2)' : ($scan->risk_level === 'medium' ? 'rgba(245, 158, 11, 0.2)' : 'rgba(16, 185, 129, 0.2)') }}; color: {{ $scan->risk_level === 'high' ? '#ef4444' : ($scan->risk_level === 'medium' ? '#f59e0b' : '#10b981') }}; border: 1px solid {{ $scan->risk_level === 'high' ? 'rgba(239, 68, 68, 0.4)' : ($scan->risk_level === 'medium' ? 'rgba(245, 158, 11, 0.4)' : 'rgba(16, 185, 129, 0.4)') }};">
                      {{ $scan->risk_level }}
                    </span>
                  </td>
                  <td style="padding: 1rem; font-weight: 700; color: #a5b4fc;">{{ $scan->risk_score }} / 100</td>
                  <td style="padding: 1rem; text-transform: uppercase; font-size: 0.8rem; color: #94a3b8; font-weight: 700;">{{ $scan->category ?? 'URL' }}</td>
                  <td style="padding: 1rem; color: #94a3b8; font-size: 0.875rem;">{{ $scan->created_at->format('M d, Y H:i') }}</td>
                </tr>
              @endforeach
            </tbody>
          </table>
        </div>

        <div style="margin-top: 1.5rem;">
          {{ $scans->links() }}
        </div>
      @endif
    </div>

  </main>
</div>
@endsection
