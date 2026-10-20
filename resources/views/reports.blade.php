@extends('layouts.app')

@section('title', 'Security Reports Archive — Block Bord AI')

@section('content')
<div style="display: flex; min-height: calc(100vh - 70px); background: #060814;">
  <x-sidebar />

  <main style="flex: 1; padding: 2.5rem; background: #060814; color: #fff;">

    <!-- Header Section -->
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2.5rem; flex-wrap: wrap; gap: 1rem;">
      <div>
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 6px;">
          <h1 style="font-size: 2.25rem; font-weight: 900; color: #fff; margin: 0;">Security Reports</h1>
          <span style="background: rgba(99, 102, 241, 0.2); color: #a5b4fc; font-weight: 700; padding: 4px 12px; border-radius: 9999px; font-size: 0.75rem; border: 1px solid rgba(99,102,241,0.3);">
            {{ $totalReports }} Generated
          </span>
        </div>
        <p style="color: #94a3b8; font-size: 0.975rem;">Cryptographically verified inspection reports and threat evidence telemetry.</p>
      </div>

      <div style="display: flex; gap: 12px;">
        <a href="{{ route('tools.home') }}" style="background: linear-gradient(135deg, #6366f1 0%, #d946ef 100%); color: #fff; padding: 0.85rem 1.6rem; border-radius: 12px; font-weight: 800; font-size: 0.925rem; text-decoration: none; box-shadow: 0 4px 20px rgba(99, 102, 241, 0.35); display: inline-flex; align-items: center; gap: 8px;">
          <span>⚡</span> New Inspection
        </a>
      </div>
    </div>

    <!-- Filter & Search Toolbar -->
    <div style="background: rgba(15, 23, 42, 0.75); backdrop-filter: blur(16px); border: 1px solid rgba(99, 102, 241, 0.2); border-radius: 18px; padding: 1.25rem 1.75rem; margin-bottom: 2rem;">
      <form method="GET" action="{{ route('reports.index') }}" style="display: flex; gap: 1rem; flex-wrap: wrap; align-items: center; justify-content: space-between;">

        <!-- Search Input -->
        <div style="flex: 1; min-width: 260px; position: relative;">
          <input type="text" name="q" value="{{ $querySearch ?? '' }}" placeholder="Search by target URL, domain, or IP..." style="width: 100%; background: #060814; border: 1px solid rgba(255,255,255,0.12); color: #fff; padding: 0.75rem 1rem 0.75rem 2.5rem; border-radius: 10px; font-size: 0.925rem; outline: none;">
          <span style="position: absolute; left: 0.85rem; top: 50%; transform: translateY(-50%); color: #64748b; font-size: 1rem;">🔍</span>
        </div>

        <!-- Risk Filter Tabs -->
        <div style="display: flex; gap: 8px; flex-wrap: wrap; align-items: center;">
          <span style="color: #64748b; font-size: 0.85rem; font-weight: 600;">Risk Filter:</span>
          @foreach(['all' => 'All Reports', 'safe' => 'Safe Only', 'medium' => 'Medium Risk', 'high' => 'High Threats'] as $key => $label)
            <a href="{{ route('reports.index', array_merge(request()->query(), ['level' => $key])) }}" style="padding: 0.5rem 1rem; border-radius: 8px; font-size: 0.85rem; font-weight: 700; text-decoration: none; transition: all 0.2s; background: {{ ($queryLevel ?? 'all') === $key ? 'rgba(99, 102, 241, 0.25)' : 'rgba(255,255,255,0.05)' }}; color: {{ ($queryLevel ?? 'all') === $key ? '#a5b4fc' : '#94a3b8' }}; border: 1px solid {{ ($queryLevel ?? 'all') === $key ? 'rgba(99, 102, 241, 0.5)' : 'rgba(255,255,255,0.08)' }};">
              {{ $label }}
            </a>
          @endforeach
        </div>

        @if($querySearch || ($queryLevel && $queryLevel !== 'all'))
          <a href="{{ route('reports.index') }}" style="color: #f87171; font-size: 0.85rem; font-weight: 600; text-decoration: none;">✕ Reset</a>
        @endif
      </form>
    </div>

    <!-- Reports Grid List -->
    @if($reports->isEmpty())
      <div style="background: rgba(15, 23, 42, 0.6); border: 1px dashed rgba(99, 102, 241, 0.3); border-radius: 20px; padding: 4rem 2rem; text-align: center;">
        <div style="font-size: 3rem; margin-bottom: 1rem;">📑</div>
        <h3 style="font-size: 1.35rem; font-weight: 800; color: #fff; margin-bottom: 0.5rem;">No security reports found</h3>
        <p style="color: #94a3b8; font-size: 0.95rem; max-width: 480px; margin: 0 auto 1.5rem;">
          @if($querySearch || $queryLevel !== 'all')
            No reports matched your active filter criteria. Try clearing search filters.
          @else
            You haven't run any security inspections yet. Scan your first URL or target to generate an encrypted report.
          @endif
        </p>
        <a href="{{ route('tools.home') }}" style="display: inline-block; background: #6366f1; color: #fff; padding: 0.75rem 1.75rem; border-radius: 10px; font-weight: 700; text-decoration: none;">
          Launch URL Inspection
        </a>
      </div>
    @else
      <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 1.5rem; margin-bottom: 2.5rem;">
        @foreach($reports as $report)
          @php
            $isHigh = $report->risk_level === 'high' || $report->risk_score >= 60;
            $isMedium = $report->risk_level === 'medium' || ($report->risk_score >= 40 && $report->risk_score < 60);
            $badgeBg = $isHigh ? 'rgba(239, 68, 68, 0.15)' : ($isMedium ? 'rgba(245, 158, 11, 0.15)' : 'rgba(16, 185, 129, 0.15)');
            $badgeColor = $isHigh ? '#ef4444' : ($isMedium ? '#f59e0b' : '#10b981');
            $badgeBorder = $isHigh ? 'rgba(239, 68, 68, 0.3)' : ($isMedium ? 'rgba(245, 158, 11, 0.3)' : 'rgba(16, 185, 129, 0.3)');
          @endphp

          <div style="background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(16px); border: 1px solid rgba(99, 102, 241, 0.2); border-radius: 20px; padding: 1.75rem; box-shadow: 0 10px 30px rgba(0,0,0,0.4); display: flex; flex-direction: column; justify-content: space-between; transition: transform 0.2s, border-color 0.2s;" onmouseover="this.style.borderColor='rgba(99,102,241,0.5)'; this.style.transform='translateY(-2px)';" onmouseout="this.style.borderColor='rgba(99,102,241,0.2)'; this.style.transform='none';">

            <div>
              <!-- Top Row: Scan ID & Badge -->
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                <span style="font-family: var(--font-mono, monospace); font-size: 0.8rem; color: #94a3b8; font-weight: 700; background: #060814; padding: 4px 8px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.06);">
                  #BB-{{ str_pad($report->id, 6, '0', STR_PAD_LEFT) }}
                </span>
                <span style="padding: 0.35rem 0.85rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 800; text-transform: uppercase; letter-spacing: 0.04em; background: {{ $badgeBg }}; color: {{ $badgeColor }}; border: 1px solid {{ $badgeBorder }};">
                  {{ strtoupper($report->risk_level ?? 'SAFE') }}
                </span>
              </div>

              <!-- Target URL / Content -->
              <h3 style="font-size: 1.15rem; font-weight: 800; color: #fff; margin: 0 0 0.5rem 0; word-break: break-all; line-height: 1.4;">
                {{ Str::limit($report->content, 65) }}
              </h3>

              <!-- Category & Timestamp -->
              <div style="display: flex; gap: 12px; color: #64748b; font-size: 0.825rem; margin-bottom: 1.25rem;">
                <span>📂 {{ ucfirst($report->category ?? 'URL') }}</span>
                <span>🕒 {{ $report->created_at ? $report->created_at->diffForHumans() : 'Recently' }}</span>
              </div>

              <!-- Mini Risk Meter -->
              <div style="background: #060814; border-radius: 12px; padding: 0.85rem 1rem; border: 1px solid rgba(255,255,255,0.05); margin-bottom: 1.5rem;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                  <span style="color: #94a3b8; font-size: 0.8rem; font-weight: 600;">Composite Risk Score</span>
                  <span style="color: {{ $badgeColor }}; font-weight: 800; font-size: 0.95rem;">{{ $report->risk_score }} / 100</span>
                </div>
                <div style="width: 100%; height: 6px; background: rgba(255,255,255,0.1); border-radius: 9999px; overflow: hidden;">
                  <div style="width: {{ min(100, max(5, $report->risk_score)) }}%; height: 100%; background: {{ $badgeColor }}; border-radius: 9999px;"></div>
                </div>
              </div>
            </div>

            <!-- Action Button -->
            <div style="display: flex; gap: 10px;">
              <a href="{{ route('reports.show', $report->id) }}" style="flex: 1; text-align: center; background: rgba(99, 102, 241, 0.15); color: #a5b4fc; border: 1px solid rgba(99, 102, 241, 0.35); padding: 0.75rem 1rem; border-radius: 10px; font-weight: 700; font-size: 0.875rem; text-decoration: none; transition: all 0.2s;" onmouseover="this.style.background='#6366f1'; this.style.color='#fff';" onmouseout="this.style.background='rgba(99, 102, 241, 0.15)'; this.style.color='#a5b4fc';">
                View Full Audit Report →
              </a>
            </div>

          </div>
        @endforeach
      </div>

      <!-- Pagination -->
      <div style="margin-top: 2rem;">
        {{ $reports->links() }}
      </div>
    @endif

  </main>
</div>
@endsection
