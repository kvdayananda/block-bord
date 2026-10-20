@extends('layouts.app')

@section('title', 'Security Inspection Report ' . $report['scan_id'] . ' — Block Bord AI')

@section('extra_head')
<style>
@media print {
  body { background: #fff !important; color: #000 !important; }
  .no-print, header, footer, aside, .sidebar { display: none !important; }
  .report-container { max-width: 100% !important; margin: 0 !important; padding: 0 !important; }
  .print-card { background: #f8fafc !important; color: #0f172a !important; border: 1px solid #cbd5e1 !important; box-shadow: none !important; }
  .print-text-dark { color: #0f172a !important; }
  .print-text-muted { color: #64748b !important; }
}
</style>
@endsection

@section('content')
<div style="display: flex; min-height: calc(100vh - 70px); background: #060814;">
  <div class="no-print">
    <x-sidebar />
  </div>

  <main class="report-container" style="flex: 1; padding: 2.5rem; background: #060814; color: #fff; max-width: 1200px; margin: 0 auto;">

    <!-- Top Action Bar (No Print) -->
    <div class="no-print" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; flex-wrap: wrap; gap: 1rem;">
      <div>
        <a href="{{ route('reports.index') }}" style="color: #a5b4fc; font-weight: 700; text-decoration: none; font-size: 0.9rem; display: inline-flex; align-items: center; gap: 6px;">
          ← Back to Reports Archive
        </a>
      </div>

      <div style="display: flex; gap: 12px; align-items: center;">
        <button onclick="window.print()" style="background: rgba(99, 102, 241, 0.15); color: #a5b4fc; border: 1px solid rgba(99, 102, 241, 0.4); padding: 0.65rem 1.25rem; border-radius: 10px; font-weight: 700; font-size: 0.875rem; cursor: pointer; display: inline-flex; align-items: center; gap: 8px; transition: background 0.2s;" onmouseover="this.style.background='rgba(99,102,241,0.25)'" onmouseout="this.style.background='rgba(99,102,241,0.15)'">
          🖨️ Export PDF / Print
        </button>
        <a href="{{ route('tools.home') }}" style="background: linear-gradient(135deg, #6366f1 0%, #d946ef 100%); color: #fff; padding: 0.65rem 1.25rem; border-radius: 10px; font-weight: 800; font-size: 0.875rem; text-decoration: none; box-shadow: 0 4px 15px rgba(99, 102, 241, 0.35);">
          ⚡ New Scan
        </a>
      </div>
    </div>

    <!-- Official Report Paper Container -->
    <div class="print-card" style="background: rgba(15, 23, 42, 0.9); backdrop-filter: blur(24px); border-radius: 24px; border: 1px solid rgba(99, 102, 241, 0.3); padding: 3rem; box-shadow: 0 20px 60px rgba(0,0,0,0.6);">

      <!-- Report Header & Brand Seal -->
      <div style="display: flex; justify-content: space-between; align-items: flex-start; padding-bottom: 2rem; border-bottom: 1px solid rgba(255,255,255,0.1); margin-bottom: 2.5rem; flex-wrap: wrap; gap: 1.5rem;">
        <div>
          <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 8px;">
            <div style="width: 42px; height: 42px; border-radius: 10px; background: linear-gradient(135deg, #6366f1, #d946ef); display: flex; align-items: center; justify-content: center; font-size: 1.4rem;">
              🛡️
            </div>
            <div>
              <h1 class="print-text-dark" style="font-size: 1.75rem; font-weight: 900; color: #fff; margin: 0; line-height: 1.2;">
                Block Bord AI Threat Inspection Report
              </h1>
              <span class="print-text-muted" style="color: #94a3b8; font-size: 0.85rem; font-weight: 600;">
                Enterprise Threat Intelligence & Heuristic Diagnostic
              </span>
            </div>
          </div>
        </div>

        <div style="text-align: right;">
          <div style="font-family: var(--font-mono, monospace); font-size: 1.1rem; font-weight: 800; color: #a5b4fc; margin-bottom: 4px;">
            {{ $report['scan_id'] }}
          </div>
          <div class="print-text-muted" style="font-size: 0.8rem; color: #64748b;">
            Generated: {{ $report['created_at'] }}
          </div>
        </div>
      </div>

      <!-- Target URL & Primary Verdict Banner -->
      <div style="background: #060814; border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; padding: 1.75rem; margin-bottom: 2.5rem;">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; margin-bottom: 1rem;">
          <span style="font-size: 0.8rem; font-weight: 700; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em;">
            Target URL / Subject
          </span>
          <span style="font-family: var(--font-mono, monospace); font-size: 0.75rem; color: #94a3b8; background: rgba(255,255,255,0.05); padding: 3px 8px; border-radius: 4px;">
            SHA256: {{ substr($report['url_hash'], 0, 16) }}...{{ substr($report['url_hash'], -8) }}
          </span>
        </div>
        <div style="font-size: 1.35rem; font-weight: 800; color: #fff; word-break: break-all; font-family: var(--font-mono, monospace); margin-bottom: 0.5rem;">
          {{ $report['url'] }}
        </div>
        <div style="font-size: 0.9rem; color: {{ $report['badge_color'] }}; font-weight: 700; display: flex; align-items: center; gap: 8px;">
          <span>●</span> {{ $report['verdict'] }}
        </div>
      </div>

      <!-- Core Metrics Row -->
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.5rem; margin-bottom: 2.5rem;">

        <!-- Risk Score Card -->
        <div style="background: #060814; border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; padding: 1.5rem;">
          <div style="color: #94a3b8; font-size: 0.85rem; font-weight: 600; margin-bottom: 6px;">Composite Risk Score</div>
          <div style="display: flex; align-items: baseline; gap: 6px;">
            <span style="font-size: 2.75rem; font-weight: 900; color: {{ $report['badge_color'] }};">
              {{ $report['risk_score'] }}
            </span>
            <span style="color: #64748b; font-size: 1.1rem; font-weight: 700;">/ 100</span>
          </div>
          <div style="font-size: 0.775rem; color: #94a3b8; margin-top: 4px;">
            Calculated across 5 engine layers
          </div>
        </div>

        <!-- Risk Classification -->
        <div style="background: #060814; border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; padding: 1.5rem;">
          <div style="color: #94a3b8; font-size: 0.85rem; font-weight: 600; margin-bottom: 12px;">Risk Classification</div>
          <span style="display: inline-block; padding: 0.5rem 1.25rem; border-radius: 9999px; font-size: 0.95rem; font-weight: 900; text-transform: uppercase; letter-spacing: 0.05em; background: {{ $report['badge_bg'] }}; color: {{ $report['badge_color'] }}; border: 1.5px solid {{ $report['badge_color'] }};">
            {{ $report['risk_level'] }}
          </span>
          <div style="font-size: 0.775rem; color: #94a3b8; margin-top: 12px;">
            Action band: {{ in_array($report['risk_level'], ['HIGH', 'CRITICAL']) ? 'Immediate Block' : 'Permitted' }}
          </div>
        </div>

        <!-- Safe Browsing Intel -->
        <div style="background: #060814; border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; padding: 1.5rem;">
          <div style="color: #94a3b8; font-size: 0.85rem; font-weight: 600; margin-bottom: 6px;">Safe Browsing Feed</div>
          <div style="font-size: 1.2rem; font-weight: 800; color: {{ $report['safe_browsing']['flagged'] ? '#ef4444' : '#10b981' }}; margin-top: 6px;">
            {{ $report['safe_browsing']['flagged'] ? '⚠️ Blacklisted' : '✅ Clean / Verified' }}
          </div>
          <div style="font-size: 0.775rem; color: #94a3b8; margin-top: 6px;">
            4 Threat feeds synchronized
          </div>
        </div>

        <!-- ML XGBoost Model -->
        <div style="background: #060814; border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; padding: 1.5rem;">
          <div style="color: #94a3b8; font-size: 0.85rem; font-weight: 600; margin-bottom: 6px;">XGBoost ML Classifier</div>
          <div style="font-size: 1.2rem; font-weight: 800; color: #fff; margin-top: 6px;">
            {{ $report['ml_engine']['confidence'] }}% <span style="font-size: 0.85rem; color: #94a3b8; font-weight: 500;">Confidence</span>
          </div>
          <div style="font-size: 0.775rem; color: #a5b4fc; margin-top: 6px;">
            Label: {{ $report['ml_engine']['prediction'] }}
          </div>
        </div>

      </div>

      <!-- Multi-Engine Risk Weight Distribution Breakdown (30/30/15/15/10) -->
      <div style="background: #060814; border: 1px solid rgba(255,255,255,0.08); border-radius: 18px; padding: 1.75rem 2rem; margin-bottom: 2.5rem;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.25rem; flex-wrap: wrap; gap: 0.5rem;">
          <h3 style="font-size: 1.1rem; font-weight: 800; color: #fff; margin: 0; display: flex; align-items: center; gap: 8px;">
            <span>⚖️</span> Universal Risk Engine Weight Allocation (100% Diagnostic Matrix)
          </h3>
          <span style="font-size: 0.8rem; color: #a5b4fc; font-weight: 700; background: rgba(99,102,241,0.15); padding: 3px 10px; border-radius: 6px; border: 1px solid rgba(99,102,241,0.3);">
            Strict Multi-Engine Pipeline
          </span>
        </div>

        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 1rem;">

          <div style="background: rgba(15, 23, 42, 0.6); padding: 1rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.05);">
            <div style="font-size: 0.75rem; color: #94a3b8; font-weight: 700; text-transform: uppercase;">Safe Browsing</div>
            <div style="font-size: 1.25rem; font-weight: 900; color: #fff; margin: 4px 0 2px 0;">30% Weight</div>
            <div style="font-size: 0.75rem; color: {{ $report['safe_browsing']['flagged'] ? '#ef4444' : '#10b981' }}; font-weight: 600;">
              {{ $report['safe_browsing']['flagged'] ? '100 / 100 Risk' : '0 / 100 Clean' }}
            </div>
          </div>

          <div style="background: rgba(15, 23, 42, 0.6); padding: 1rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.05);">
            <div style="font-size: 0.75rem; color: #94a3b8; font-weight: 700; text-transform: uppercase;">XGBoost ML</div>
            <div style="font-size: 1.25rem; font-weight: 900; color: #fff; margin: 4px 0 2px 0;">30% Weight</div>
            <div style="font-size: 0.75rem; color: #a5b4fc; font-weight: 600;">
              {{ round($report['ml_engine']['confidence'], 1) }}% Confidence
            </div>
          </div>

          <div style="background: rgba(15, 23, 42, 0.6); padding: 1rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.05);">
            <div style="font-size: 0.75rem; color: #94a3b8; font-weight: 700; text-transform: uppercase;">Domain Intel</div>
            <div style="font-size: 1.25rem; font-weight: 900; color: #fff; margin: 4px 0 2px 0;">15% Weight</div>
            <div style="font-size: 0.75rem; color: #38bdf8; font-weight: 600;">
              DNS & TLD Scoring
            </div>
          </div>

          <div style="background: rgba(15, 23, 42, 0.6); padding: 1rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.05);">
            <div style="font-size: 0.75rem; color: #94a3b8; font-weight: 700; text-transform: uppercase;">URL Heuristics</div>
            <div style="font-size: 1.25rem; font-weight: 900; color: #fff; margin: 4px 0 2px 0;">15% Weight</div>
            <div style="font-size: 0.75rem; color: #f59e0b; font-weight: 600;">
              Lexical & Entropy
            </div>
          </div>

          <div style="background: rgba(15, 23, 42, 0.6); padding: 1rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.05);">
            <div style="font-size: 0.75rem; color: #94a3b8; font-weight: 700; text-transform: uppercase;">SSL & Headers</div>
            <div style="font-size: 1.25rem; font-weight: 900; color: #fff; margin: 4px 0 2px 0;">10% Weight</div>
            <div style="font-size: 0.75rem; color: {{ $report['ssl']['valid'] ? '#10b981' : '#ef4444' }}; font-weight: 600;">
              {{ $report['ssl']['valid'] ? 'TLS Active' : 'Insecure HTTP' }}
            </div>
          </div>

        </div>
      </div>

      <!-- AI Threat Analysis & Plain-Language Summary -->
      <div style="background: rgba(99, 102, 241, 0.08); border: 1px solid rgba(99, 102, 241, 0.3); border-radius: 18px; padding: 2rem; margin-bottom: 2.5rem;">
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 1rem;">
          <span style="font-size: 1.4rem;">🤖</span>
          <h3 style="font-size: 1.2rem; font-weight: 800; color: #fff; margin: 0;">AI Threat Intelligence Summary</h3>
        </div>
        <p style="color: #cbd5e1; font-size: 0.975rem; line-height: 1.7; margin: 0;">
          {{ $report['ai_summary'] }}
        </p>
      </div>

      <!-- Technical Evidence & Heuristics Breakdown -->
      <div style="margin-bottom: 2.5rem;">
        <h3 style="font-size: 1.25rem; font-weight: 800; color: #fff; margin-bottom: 1.25rem;">
          Diagnostic Heuristics & Security Indicators
        </h3>

        <div style="display: flex; flex-direction: column; gap: 12px;">
          @foreach($report['heuristics'] as $h)
            <div style="background: #060814; border: 1px solid {{ $h['status'] === 'critical' ? 'rgba(239, 68, 68, 0.3)' : ($h['status'] === 'warning' ? 'rgba(245, 158, 11, 0.3)' : 'rgba(255,255,255,0.06)') }}; border-radius: 14px; padding: 1.25rem 1.5rem; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem;">
              <div>
                <div style="font-weight: 700; color: #fff; font-size: 0.975rem; margin-bottom: 4px;">
                  {{ $h['name'] }}
                </div>
                <div style="color: #94a3b8; font-size: 0.85rem;">
                  {{ $h['detail'] }}
                </div>
              </div>

              <div>
                @if($h['status'] === 'critical')
                  <span style="background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239,68,68,0.3); font-weight: 800; font-size: 0.75rem; padding: 4px 10px; border-radius: 9999px; text-transform: uppercase;">
                    Critical
                  </span>
                @elseif($h['status'] === 'warning')
                  <span style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; border: 1px solid rgba(245,158,11,0.3); font-weight: 800; font-size: 0.75rem; padding: 4px 10px; border-radius: 9999px; text-transform: uppercase;">
                    Warning
                  </span>
                @else
                  <span style="background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16,185,129,0.3); font-weight: 800; font-size: 0.75rem; padding: 4px 10px; border-radius: 9999px; text-transform: uppercase;">
                    Clean
                  </span>
                @endif
              </div>
            </div>
          @endforeach
        </div>
      </div>

      <!-- SSL & Certificate Details Grid -->
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5rem; margin-bottom: 2.5rem;">

        <div style="background: #060814; border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; padding: 1.5rem;">
          <h4 style="font-size: 1rem; font-weight: 800; color: #fff; margin: 0 0 1rem 0;">🔒 SSL / TLS Certificate</h4>
          <div style="display: flex; flex-direction: column; gap: 8px; font-size: 0.875rem;">
            <div style="display: flex; justify-content: space-between;"><span style="color: #64748b;">Status:</span> <span style="font-weight: 700; color: {{ $report['ssl']['valid'] ? '#10b981' : '#ef4444' }};">{{ $report['ssl']['valid'] ? 'Valid Certificate' : 'Invalid / Insecure' }}</span></div>
            <div style="display: flex; justify-content: space-between;"><span style="color: #64748b;">Protocol:</span> <span style="color: #cbd5e1;">{{ $report['ssl']['protocol'] }}</span></div>
            <div style="display: flex; justify-content: space-between;"><span style="color: #64748b;">Issuer:</span> <span style="color: #cbd5e1;">{{ $report['ssl']['issuer'] }}</span></div>
            <div style="display: flex; justify-content: space-between;"><span style="color: #64748b;">HSTS:</span> <span style="color: #cbd5e1;">{{ $report['ssl']['hsts_active'] ? 'Enforced' : 'Disabled' }}</span></div>
          </div>
        </div>

        <div style="background: #060814; border: 1px solid rgba(255,255,255,0.08); border-radius: 16px; padding: 1.5rem;">
          <h4 style="font-size: 1rem; font-weight: 800; color: #fff; margin: 0 0 1rem 0;">🌐 Host Intelligence</h4>
          <div style="display: flex; flex-direction: column; gap: 8px; font-size: 0.875rem;">
            <div style="display: flex; justify-content: space-between;"><span style="color: #64748b;">Target Host:</span> <span style="color: #cbd5e1; font-family: var(--font-mono, monospace);">{{ $report['host'] }}</span></div>
            <div style="display: flex; justify-content: space-between;"><span style="color: #64748b;">Category:</span> <span style="color: #cbd5e1;">{{ $report['category'] }}</span></div>
            <div style="display: flex; justify-content: space-between;"><span style="color: #64748b;">Scam Intent:</span> <span style="color: #cbd5e1;">{{ $report['scam_intent'] }}</span></div>
            <div style="display: flex; justify-content: space-between;"><span style="color: #64748b;">Inspection ID:</span> <span style="color: #a5b4fc; font-family: var(--font-mono, monospace);">{{ $report['scan_id'] }}</span></div>
          </div>
        </div>

      </div>

      <!-- Actionable Mitigation Checklist -->
      <div style="background: #060814; border: 1px solid rgba(255,255,255,0.08); border-radius: 18px; padding: 2rem;">
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 1.25rem;">
          <span style="font-size: 1.3rem;">📋</span>
          <h3 style="font-size: 1.2rem; font-weight: 800; color: #fff; margin: 0;">Recommended Security Actions</h3>
        </div>

        <div style="display: flex; flex-direction: column; gap: 10px;">
          @foreach($report['recommendations'] as $idx => $rec)
            <div style="display: flex; align-items: flex-start; gap: 12px; font-size: 0.95rem; color: #cbd5e1;">
              <span style="background: rgba(99, 102, 241, 0.2); color: #a5b4fc; width: 24px; height: 24px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 0.8rem; font-weight: 800; flex-shrink: 0; margin-top: 2px;">
                {{ $idx + 1 }}
              </span>
              <span>{{ $rec }}</span>
            </div>
          @endforeach
        </div>
      </div>

      <!-- Report Footer Stamp -->
      <div style="margin-top: 3rem; padding-top: 1.5rem; border-top: 1px solid rgba(255,255,255,0.08); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; font-size: 0.8rem; color: #64748b;">
        <div>
          Verified by <strong>Block Bord AI Threat Engine v8.0</strong>
        </div>
        <div>
          Confidential & Proprietary Cybersecurity Assessment
        </div>
      </div>

    </div>

  </main>
</div>
@endsection
