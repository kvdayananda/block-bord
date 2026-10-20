@extends('layouts.app')

@section('title', 'Personal Security Score — Block Bord AI')

@section('content')
<div style="display: flex; min-height: calc(100vh - 70px); background: #060814;">
  <x-sidebar />

  <main style="flex: 1; padding: 2.5rem; background: #060814; color: #fff;">

    <!-- Header Section -->
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2.5rem; flex-wrap: wrap; gap: 1rem;">
      <div>
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 6px;">
          <h1 style="font-size: 2.25rem; font-weight: 900; color: #fff; margin: 0;">Personal Security Score</h1>
          <span style="background: rgba(16, 185, 129, 0.2); color: #34d399; font-weight: 800; padding: 4px 12px; border-radius: 9999px; font-size: 0.8rem; border: 1px solid rgba(16,185,129,0.3);">
            GRADE {{ $scoreData['grade'] }}
          </span>
        </div>
        <p style="color: #94a3b8; font-size: 0.975rem;">Continuous heuristic evaluation of your digital posture, identity safeguards, and perimeter rules.</p>
      </div>

      <div style="display: flex; gap: 12px;">
        <a href="{{ route('tools.home') }}" style="background: linear-gradient(135deg, #6366f1 0%, #d946ef 100%); color: #fff; padding: 0.85rem 1.6rem; border-radius: 12px; font-weight: 800; font-size: 0.925rem; text-decoration: none; box-shadow: 0 4px 20px rgba(99, 102, 241, 0.35);">
          ⚡ Run Posture Scan
        </a>
      </div>
    </div>

    <!-- Main Score Hero Card with Circular Gauge -->
    <div style="background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(20px); border: 1px solid rgba(99, 102, 241, 0.25); border-radius: 24px; padding: 2.5rem; margin-bottom: 3rem; box-shadow: 0 16px 40px rgba(0,0,0,0.5);">
      <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 2.5rem;">

        <!-- Left: Circular Meter SVG -->
        <div style="display: flex; align-items: center; gap: 2rem;">
          <div style="position: relative; width: 150px; height: 150px; display: flex; align-items: center; justify-content: center;">
            <svg style="width: 150px; height: 150px; transform: rotate(-90deg);" viewBox="0 0 120 120">
              <circle cx="60" cy="60" r="50" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="10" />
              @php
                $radius = 50;
                $circumference = 2 * 3.14159265 * $radius;
                $offset = $circumference - (($scoreData['score'] / 100) * $circumference);
              @endphp
              <circle cx="60" cy="60" r="50" fill="none" stroke="{{ $scoreData['color'] }}" stroke-width="10" stroke-linecap="round" stroke-dasharray="{{ $circumference }}" stroke-dashoffset="{{ $offset }}" style="transition: stroke-dashoffset 1s ease-in-out;" />
            </svg>
            <div style="position: absolute; text-align: center;">
              <div style="font-size: 2.4rem; font-weight: 900; color: #fff; line-height: 1;">
                {{ $scoreData['score'] }}
              </div>
              <div style="font-size: 0.75rem; font-weight: 700; color: #94a3b8; text-transform: uppercase; margin-top: 4px;">
                out of 100
              </div>
            </div>
          </div>

          <div>
            <span style="color: {{ $scoreData['color'] }}; font-weight: 800; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em;">
              ● {{ $scoreData['rating'] }}
            </span>
            <h2 style="font-size: 1.75rem; font-weight: 900; color: #fff; margin: 6px 0 8px 0;">
              Your Defense Rating is {{ $scoreData['grade'] }}
            </h2>
            <p style="color: #94a3b8; font-size: 0.925rem; max-width: 480px; margin: 0;">
              @if($scoreData['score'] >= 85)
                Excellent! Your defensive perimeter is well-configured with multi-factor authentication and threat surveillance.
              @else
                Action recommended: Complete the pending security milestones below to harden your digital perimeter.
              @endif
            </p>
          </div>
        </div>

        <!-- Right: Stat Pills -->
        <div style="display: flex; gap: 1rem; flex-wrap: wrap;">
          <div style="background: #060814; border: 1px solid rgba(255,255,255,0.06); border-radius: 14px; padding: 1.25rem 1.5rem; text-align: center; min-width: 130px;">
            <div style="color: #94a3b8; font-size: 0.75rem; font-weight: 700; text-transform: uppercase;">Inspections</div>
            <div style="font-size: 1.75rem; font-weight: 900; color: #fff; margin-top: 4px;">{{ $scoreData['total_scans'] }}</div>
          </div>
          <div style="background: #060814; border: 1px solid rgba(255,255,255,0.06); border-radius: 14px; padding: 1.25rem 1.5rem; text-align: center; min-width: 130px;">
            <div style="color: #94a3b8; font-size: 0.75rem; font-weight: 700; text-transform: uppercase;">Blocked Threats</div>
            <div style="font-size: 1.75rem; font-weight: 900; color: #ef4444; margin-top: 4px;">{{ $scoreData['threats_blocked'] }}</div>
          </div>
        </div>

      </div>
    </div>

    <!-- Security Posture Factors Checklist -->
    <div style="margin-bottom: 3rem;">
      <h3 style="font-size: 1.35rem; font-weight: 800; color: #fff; margin-bottom: 1.25rem;">
        Security Posture Factors Breakdown
      </h3>

      <div style="display: flex; flex-direction: column; gap: 1.25rem;">
        @foreach($scoreData['factors'] as $factor)
          @php
            $isPassed = $factor['status'] === 'passed';
            $isWarning = $factor['status'] === 'warning';
            $isAlert = $factor['status'] === 'alert';
            $statusColor = $isPassed ? '#10b981' : ($isWarning ? '#f59e0b' : ($isAlert ? '#ef4444' : '#3b82f6'));
            $statusBg = $isPassed ? 'rgba(16, 185, 129, 0.15)' : ($isWarning ? 'rgba(245, 158, 11, 0.15)' : ($isAlert ? 'rgba(239, 68, 68, 0.15)' : 'rgba(59, 130, 246, 0.15)'));
          @endphp

          <div style="background: rgba(15, 23, 42, 0.8); backdrop-filter: blur(16px); border: 1px solid rgba(255,255,255,0.08); border-radius: 18px; padding: 1.5rem 1.75rem; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1.5rem;">

            <div style="display: flex; align-items: flex-start; gap: 16px; flex: 1; min-width: 280px;">
              <div style="width: 40px; height: 40px; border-radius: 12px; background: {{ $statusBg }}; color: {{ $statusColor }}; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; flex-shrink: 0;">
                @if($isPassed) ✓ @elseif($isWarning) ⚠️ @elseif($isAlert) 🛡️ @else ℹ️ @endif
              </div>

              <div>
                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 4px;">
                  <h4 style="font-size: 1.1rem; font-weight: 800; color: #fff; margin: 0;">
                    {{ $factor['title'] }}
                  </h4>
                  <span style="padding: 2px 8px; border-radius: 6px; font-size: 0.75rem; font-weight: 800; background: {{ $statusBg }}; color: {{ $statusColor }};">
                    {{ $factor['points'] }} / {{ $factor['max_points'] }} PTS
                  </span>
                </div>
                <p style="color: #94a3b8; font-size: 0.9rem; margin: 0; line-height: 1.5;">
                  {{ $factor['description'] }}
                </p>
              </div>
            </div>

            <div>
              <a href="{{ $factor['action_route'] }}" style="display: inline-block; padding: 0.65rem 1.25rem; border-radius: 10px; font-size: 0.85rem; font-weight: 700; text-decoration: none; transition: all 0.2s; background: {{ $isPassed ? 'rgba(255,255,255,0.06)' : 'linear-gradient(135deg, #6366f1, #d946ef)' }}; color: {{ $isPassed ? '#cbd5e1' : '#fff' }}; border: 1px solid {{ $isPassed ? 'rgba(255,255,255,0.1)' : 'transparent' }};">
                {{ $factor['action_label'] }} →
              </a>
            </div>

          </div>
        @endforeach
      </div>
    </div>

  </main>
</div>
@endsection
