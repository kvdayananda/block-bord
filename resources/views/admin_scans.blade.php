@extends('layouts.app')

@section('title', 'All Platform Scans — Admin Console — Block Bord AI')

@section('content')
<div style="display: flex; min-height: calc(100vh - 70px); background: #060814;">
  <x-sidebar />

  <main style="flex: 1; padding: 2.5rem; background: #060814; color: #fff;">

    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; flex-wrap: wrap; gap: 1rem;">
      <div>
        <h1 style="font-size: 2.25rem; font-weight: 900; color: #fff; margin: 0 0 4px 0;">Platform Scan Management</h1>
        <p style="color: #94a3b8; font-size: 0.95rem; margin: 0;">Global surveillance index of all analyzed targets across public and authenticated users.</p>
      </div>

      <div style="display: flex; gap: 1rem;">
        <span style="background: rgba(99, 102, 241, 0.2); color: #a5b4fc; padding: 6px 14px; border-radius: 9999px; font-weight: 800; font-size: 0.85rem; border: 1px solid rgba(99,102,241,0.3);">
          {{ $totalScansCount }} Total Inspections
        </span>
        <span style="background: rgba(239, 68, 68, 0.2); color: #f87171; padding: 6px 14px; border-radius: 9999px; font-weight: 800; font-size: 0.85rem; border: 1px solid rgba(239,68,68,0.3);">
          {{ $threatCount }} Threats Intercepted
        </span>
      </div>
    </div>

    <!-- Admin Nav Tabs -->
    <x-admin-nav />

    <!-- Filters & Search Toolbar -->
    <div style="background: rgba(15, 23, 42, 0.75); border: 1px solid rgba(99, 102, 241, 0.2); border-radius: 16px; padding: 1.25rem 1.5rem; margin-bottom: 2rem;">
      <form method="GET" action="{{ route('admin.scans') }}" style="display: flex; gap: 1rem; flex-wrap: wrap; align-items: center; justify-content: space-between;">

        <div style="flex: 1; min-width: 260px; position: relative;">
          <input type="text" name="search" value="{{ $currentSearch ?? '' }}" placeholder="Search scan content, domain, or SHA256 hash..." style="width: 100%; background: #060814; border: 1px solid rgba(255,255,255,0.12); color: #fff; padding: 0.65rem 1rem 0.65rem 2.5rem; border-radius: 10px; font-size: 0.9rem; outline: none;">
          <span style="position: absolute; left: 0.85rem; top: 50%; transform: translateY(-50%); color: #64748b;">🔍</span>
        </div>

        <div style="display: flex; gap: 8px; flex-wrap: wrap; align-items: center;">
          <span style="color: #64748b; font-size: 0.85rem; font-weight: 600;">Risk Band:</span>
          @foreach(['all' => 'All Bands', 'safe' => 'Safe (0-19)', 'low' => 'Low (20-39)', 'medium' => 'Medium (40-59)', 'high' => 'High (60-79)', 'critical' => 'Critical (80-100)'] as $key => $label)
            <a href="{{ route('admin.scans', array_merge(request()->query(), ['risk' => $key])) }}" style="padding: 0.45rem 0.85rem; border-radius: 8px; font-size: 0.8rem; font-weight: 700; text-decoration: none; background: {{ ($currentRisk ?? 'all') === $key ? 'rgba(99, 102, 241, 0.25)' : 'rgba(255,255,255,0.05)' }}; color: {{ ($currentRisk ?? 'all') === $key ? '#a5b4fc' : '#94a3b8' }}; border: 1px solid {{ ($currentRisk ?? 'all') === $key ? 'rgba(99, 102, 241, 0.5)' : 'rgba(255,255,255,0.08)' }};">
              {{ $label }}
            </a>
          @endforeach
        </div>

      </form>
    </div>

    <!-- Scans Table -->
    <div style="background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(20px); border-radius: 20px; border: 1px solid rgba(99, 102, 241, 0.2); padding: 1.5rem; box-shadow: 0 12px 32px rgba(0,0,0,0.5);">
      <div style="overflow-x: auto;">
        <table style="width: 100%; border-collapse: collapse; text-align: left; color: #cbd5e1;">
          <thead>
            <tr style="border-bottom: 1px solid rgba(99, 102, 241, 0.2); color: #94a3b8; font-size: 0.825rem; text-transform: uppercase; letter-spacing: 0.05em;">
              <th style="padding: 1rem;">ID</th>
              <th style="padding: 1rem;">Target Evaluated</th>
              <th style="padding: 1rem;">Risk Band</th>
              <th style="padding: 1rem;">Score</th>
              <th style="padding: 1rem;">Origin User</th>
              <th style="padding: 1rem;">Date</th>
              <th style="padding: 1rem; text-align: right;">Actions</th>
            </tr>
          </thead>
          <tbody>
            @foreach($scans as $scan)
              @php
                $isCritical = $scan->risk_level === 'critical' || $scan->risk_score >= 80;
                $isHigh = $scan->risk_level === 'high' || ($scan->risk_score >= 60 && $scan->risk_score < 80);
                $isMedium = $scan->risk_level === 'medium' || ($scan->risk_score >= 40 && $scan->risk_score < 60);
                $badgeBg = $isCritical ? 'rgba(239, 68, 68, 0.2)' : ($isHigh ? 'rgba(248, 113, 113, 0.2)' : ($isMedium ? 'rgba(245, 158, 11, 0.2)' : 'rgba(16, 185, 129, 0.2)'));
                $badgeColor = $isCritical ? '#ef4444' : ($isHigh ? '#f87171' : ($isMedium ? '#f59e0b' : '#10b981'));
              @endphp

              <tr style="border-bottom: 1px solid rgba(255,255,255,0.05); transition: background 0.2s;" onmouseover="this.style.background='rgba(99,102,241,0.08)'" onmouseout="this.style.background='transparent'">
                <td style="padding: 1rem; font-family: var(--font-mono, monospace); color: #64748b;">#{{ $scan->id }}</td>
                <td style="padding: 1rem; font-weight: 700; color: #fff; word-break: break-all; max-width: 320px;">
                  {{ Str::limit($scan->content, 55) }}
                </td>
                <td style="padding: 1rem;">
                  <span style="padding: 0.3rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 800; text-transform: uppercase; background: {{ $badgeBg }}; color: {{ $badgeColor }}; border: 1px solid {{ $badgeColor }};">
                    {{ strtoupper($scan->risk_level ?? 'SAFE') }}
                  </span>
                </td>
                <td style="padding: 1rem; font-weight: 800; color: #a5b4fc;">{{ $scan->risk_score }} / 100</td>
                <td style="padding: 1rem; color: #94a3b8; font-size: 0.85rem;">
                  {{ $scan->user ? $scan->user->username : 'Guest / Extension' }}
                </td>
                <td style="padding: 1rem; color: #64748b; font-size: 0.825rem;">{{ $scan->created_at->format('M d, Y H:i') }}</td>
                <td style="padding: 1rem; text-align: right;">
                  <div style="display: inline-flex; gap: 8px;">
                    <a href="{{ route('reports.show', $scan->id) }}" style="background: rgba(99, 102, 241, 0.15); color: #a5b4fc; border: 1px solid rgba(99, 102, 241, 0.3); padding: 4px 10px; border-radius: 6px; font-size: 0.75rem; font-weight: 700; text-decoration: none;">
                      Report
                    </a>
                    <form method="POST" action="{{ route('admin.scans.delete', $scan->id) }}" onsubmit="return confirm('Delete this scan audit record?');">
                      @csrf
                      @method('DELETE')
                      <button type="submit" style="background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); padding: 4px 8px; border-radius: 6px; font-size: 0.75rem; font-weight: 700; cursor: pointer;">
                        ✕
                      </button>
                    </form>
                  </div>
                </td>
              </tr>
            @endforeach
          </tbody>
        </table>
      </div>

      <div style="margin-top: 1.5rem;">
        {{ $scans->links() }}
      </div>
    </div>

  </main>
</div>
@endsection
