@extends('layouts.app')

@section('title', 'Scan History Logs — Block Bord AI')

@section('content')
<div style="display: flex; min-height: calc(100vh - 70px); background: #060814;">
  <x-sidebar />

  <main style="flex: 1; padding: 2.5rem; background: #060814; color: #fff;">
    
    <!-- Header Section -->
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2.5rem; flex-wrap: wrap; gap: 1rem;">
      <div>
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 6px;">
          <h1 style="font-size: 2.25rem; font-weight: 900; color: #fff; margin: 0;">Scan History & Logs</h1>
        </div>
        <p style="color: #94a3b8; font-size: 0.975rem;">Complete chronological audit log of all URLs, domains, and IP threat inspections.</p>
      </div>

      <div style="display: flex; gap: 12px;">
        <a href="{{ route('tools.home') }}" style="background: linear-gradient(135deg, #6366f1 0%, #d946ef 100%); color: #fff; padding: 0.85rem 1.6rem; border-radius: 12px; font-weight: 800; font-size: 0.925rem; text-decoration: none; box-shadow: 0 4px 20px rgba(99, 102, 241, 0.35);">
          ⚡ Launch Security Scan
        </a>
      </div>
    </div>

    <!-- Filter Bar -->
    <div style="background: rgba(15, 23, 42, 0.75); backdrop-filter: blur(16px); border: 1px solid rgba(99, 102, 241, 0.2); border-radius: 18px; padding: 1.25rem 1.75rem; margin-bottom: 2rem;">
      <form method="GET" action="{{ route('history') }}" style="display: flex; gap: 1rem; flex-wrap: wrap; align-items: center; justify-content: space-between;">

        <div style="flex: 1; min-width: 260px; position: relative;">
          <input type="text" name="search" value="{{ $currentSearch ?? '' }}" placeholder="Search scan targets..." style="width: 100%; background: #060814; border: 1px solid rgba(255,255,255,0.12); color: #fff; padding: 0.75rem 1rem 0.75rem 2.5rem; border-radius: 10px; font-size: 0.925rem; outline: none;">
          <span style="position: absolute; left: 0.85rem; top: 50%; transform: translateY(-50%); color: #64748b; font-size: 1rem;">🔍</span>
        </div>

        <div style="display: flex; gap: 8px; flex-wrap: wrap; align-items: center;">
          <span style="color: #64748b; font-size: 0.85rem; font-weight: 600;">Risk Level:</span>
          @foreach(['' => 'All', 'safe' => 'Safe', 'medium' => 'Medium', 'high' => 'High'] as $key => $label)
            <a href="{{ route('history', array_merge(request()->query(), ['risk' => $key])) }}" style="padding: 0.5rem 0.9rem; border-radius: 8px; font-size: 0.85rem; font-weight: 700; text-decoration: none; background: {{ ($currentRisk ?? '') === $key ? 'rgba(99, 102, 241, 0.25)' : 'rgba(255,255,255,0.05)' }}; color: {{ ($currentRisk ?? '') === $key ? '#a5b4fc' : '#94a3b8' }}; border: 1px solid {{ ($currentRisk ?? '') === $key ? 'rgba(99, 102, 241, 0.5)' : 'rgba(255,255,255,0.08)' }};">
              {{ $label }}
            </a>
          @endforeach
        </div>

        @if($currentSearch || $currentRisk)
          <a href="{{ route('history') }}" style="color: #f87171; font-size: 0.85rem; font-weight: 600; text-decoration: none;">✕ Reset</a>
        @endif
      </form>
    </div>

    <!-- Table Container -->
    <div style="background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(20px); border-radius: 20px; border: 1px solid rgba(99, 102, 241, 0.2); padding: 2rem; box-shadow: 0 12px 32px rgba(0,0,0,0.5);">
      @if($scans->isEmpty())
        <div style="text-align: center; padding: 3rem 1rem; color: #94a3b8;">
          <div style="font-size: 2.5rem; margin-bottom: 1rem;">📜</div>
          <p style="font-size: 1.1rem; margin-bottom: 1rem;">No scan history recorded.</p>
          <a href="{{ route('tools.home') }}" style="display: inline-block; background: #6366f1; color: #fff; padding: 0.75rem 1.5rem; border-radius: 10px; font-weight: 700; text-decoration: none;">Launch Scan</a>
        </div>
      @else
        <div class="table-responsive" style="overflow-x: auto;">
          <table style="width: 100%; border-collapse: collapse; text-align: left; color: #cbd5e1;">
            <thead>
              <tr style="border-bottom: 1px solid rgba(99, 102, 241, 0.2); color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em;">
                <th style="padding: 1rem;">Target Content</th>
                <th style="padding: 1rem;">Classification</th>
                <th style="padding: 1rem;">Risk Score</th>
                <th style="padding: 1rem;">Category</th>
                <th style="padding: 1rem;">Scanned Date</th>
                <th style="padding: 1rem; text-align: right;">Action</th>
              </tr>
            </thead>
            <tbody>
              @foreach($scans as $scan)
                <tr style="border-bottom: 1px solid rgba(255,255,255,0.05); transition: background 0.2s;" onmouseover="this.style.background='rgba(99,102,241,0.08)'" onmouseout="this.style.background='transparent'">
                  <td data-label="Target Content" style="padding: 1rem; font-weight: 600; color: #fff; word-break: break-all;">
                    {{ Str::limit($scan->content, 60) }}
                  </td>
                  <td data-label="Classification" style="padding: 1rem;">
                    <span style="padding: 0.35rem 0.85rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.04em; background: {{ $scan->risk_level === 'high' ? 'rgba(239, 68, 68, 0.2)' : ($scan->risk_level === 'medium' ? 'rgba(245, 158, 11, 0.2)' : 'rgba(16, 185, 129, 0.2)') }}; color: {{ $scan->risk_level === 'high' ? '#ef4444' : ($scan->risk_level === 'medium' ? '#f59e0b' : '#10b981') }}; border: 1px solid {{ $scan->risk_level === 'high' ? 'rgba(239, 68, 68, 0.4)' : ($scan->risk_level === 'medium' ? 'rgba(245, 158, 11, 0.4)' : 'rgba(16, 185, 129, 0.4)') }};">
                      {{ $scan->risk_level }}
                    </span>
                  </td>
                  <td data-label="Risk Score" style="padding: 1rem; font-weight: 700; color: #a5b4fc;">{{ $scan->risk_score }} / 100</td>
                  <td data-label="Category" style="padding: 1rem; text-transform: uppercase; font-size: 0.8rem; color: #94a3b8; font-weight: 700;">{{ $scan->category ?? 'URL' }}</td>
                  <td data-label="Scanned Date" style="padding: 1rem; color: #94a3b8; font-size: 0.875rem;">{{ $scan->created_at->format('M d, Y H:i') }}</td>
                  <td data-label="Action" style="padding: 1rem; text-align: right;">
                    <a href="{{ route('reports.show', $scan->id) }}" style="color: #a5b4fc; font-size: 0.825rem; font-weight: 700; text-decoration: none; background: rgba(99,102,241,0.15); padding: 5px 12px; border-radius: 8px; border: 1px solid rgba(99,102,241,0.3);">
                      Full Audit Report →
                    </a>
                  </td>
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
