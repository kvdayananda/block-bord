@extends('layouts.app')
@section('title', 'Scan History — Block Bord AI')
@section('content')
<div style="display: flex; min-height: calc(100vh - 70px);">
  <x-sidebar />
  <main style="flex: 1; padding: 2.5rem; background: #0f0f17; color: #fff;">
    <h1 style="font-size: 2rem; font-weight: 800; margin-bottom: 1.5rem;">Scan History</h1>
    <div style="background: #1e1e2e; border-radius: 12px; padding: 1.5rem; border: 1px solid rgba(255,255,255,0.08);">
      @if($scans->isEmpty())
        <p style="color: #94a3b8;">No history records found.</p>
      @else
        <table style="width: 100%; border-collapse: collapse; text-align: left;">
          <thead>
            <tr style="border-bottom: 1px solid #33334d; color: #94a3b8;">
              <th style="padding: 0.75rem;">URL / Content</th>
              <th style="padding: 0.75rem;">Risk</th>
              <th style="padding: 0.75rem;">Score</th>
              <th style="padding: 0.75rem;">Date</th>
            </tr>
          </thead>
          <tbody>
            @foreach($scans as $scan)
              <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                <td style="padding: 0.75rem;">{{ $scan->content }}</td>
                <td style="padding: 0.75rem;"><span style="padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: 700; background: #33334d;">{{ $scan->risk_level }}</span></td>
                <td style="padding: 0.75rem;">{{ $scan->risk_score }}</td>
                <td style="padding: 0.75rem;">{{ $scan->created_at->format('M d, Y H:i') }}</td>
              </tr>
            @endforeach
          </tbody>
        </table>
        <div style="margin-top: 1.5rem;">
          {{ $scans->links() }}
        </div>
      @endif
    </div>
  </main>
</div>
@endsection
