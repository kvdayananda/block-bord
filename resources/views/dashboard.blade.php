@extends('layouts.app')

@section('title', 'Security Command Center — Block Bord AI')

@section('content')
<div class="command-center-layout">
  <x-sidebar />

  <main class="command-center-main">
    
    <!-- Top Telemetry & Greeting Bar -->
    <div class="dashboard-hero">
      <div class="hero-left">
        <div class="hero-badge-row">
          <span class="pulse-indicator">
            <span class="pulse-dot"></span>
            <span class="pulse-text">NEURAL SHIELD ACTIVE</span>
          </span>
          <span class="tier-badge">
            <span class="tier-icon">⚡</span> {{ strtoupper($user->plan ?? 'FREE') }} TIER
          </span>
          <span class="latency-badge">
            <span class="dot-green"></span> ML Engine: 16ms
          </span>
        </div>
        <h1 class="hero-title">Security Command Center</h1>
        <p class="hero-subtitle">
          Welcome back, <strong class="text-highlight">{{ $user->username }}</strong>. Real-time perimeter defense and threat intelligence are active.
        </p>
      </div>

      <div class="hero-actions">
        <a href="{{ route('tools.home') }}" class="btn-hero-primary">
          <span class="btn-icon">⚡</span>
          <span>Security Suite</span>
        </a>
        <a href="{{ route('ai.page') }}" class="btn-hero-secondary">
          <span class="btn-icon">🤖</span>
          <span>AI Copilot</span>
        </a>
      </div>
    </div>

    <!-- Threat Alert Banner if unread alerts -->
    @if(isset($unreadNotificationsCount) && $unreadNotificationsCount > 0)
      <div class="security-alert-banner">
        <div class="alert-content">
          <div class="alert-icon-wrap">🔔</div>
          <div>
            <div class="alert-title">
              {{ $unreadNotificationsCount }} Security Notification{{ $unreadNotificationsCount > 1 ? 's' : '' }} Requiring Attention
            </div>
            <div class="alert-desc">Review anomalous connection attempts, risk threshold alerts, and perimeter recommendations.</div>
          </div>
        </div>
        <a href="{{ route('notifications.index') }}" class="alert-action-btn">
          Review Alerts →
        </a>
      </div>
    @endif

    <!-- Real-Time Quick Scanner Widget -->
    <div class="quick-scanner-card">
      <div class="scanner-header">
        <div class="scanner-title-group">
          <span class="scanner-icon">⚡</span>
          <div>
            <h3 class="scanner-heading">Instant Multi-Layer Threat Scanner</h3>
            <p class="scanner-subheading">Analyze any URL, domain, IP, or suspicious text across 6 AI intelligence layers in sub-seconds.</p>
          </div>
        </div>
        <div class="scanner-layers-indicator">
          <span class="layer-tag">XGBoost ML</span>
          <span class="layer-tag">Safe Browsing</span>
          <span class="layer-tag">DNS & WHOIS</span>
          <span class="layer-tag">Heuristics</span>
        </div>
      </div>

      <form id="quickScanForm" class="quick-scanner-form">
        <div class="scanner-input-container">
          <span class="input-protocol-badge">https://</span>
          <input
            type="text"
            id="quickScanInput"
            class="scanner-input"
            placeholder="example.com, suspicious-link.net, or IP address..."
            autocomplete="off"
            required
          />
          <button type="button" id="clearScanInput" class="btn-clear-input" title="Clear">✕</button>
          <button type="submit" id="quickScanSubmitBtn" class="scanner-submit-btn">
            <span class="btn-text">Inspect Target</span>
            <span class="btn-spinner" style="display: none;"></span>
          </button>
        </div>
      </form>

      <!-- Dynamic Scan Result Feedback Container -->
      <div id="quickScanResult" class="quick-scan-result" style="display: none;">
        <!-- Injected via JavaScript -->
      </div>
    </div>

    <!-- Core Security Metrics Grid -->
    <div class="metrics-grid">
      
      <!-- Metric 1: Total Analyzed -->
      <div class="metric-card cyan-glow">
        <div class="metric-header">
          <span class="metric-label">Total Analyzed</span>
          <div class="metric-icon-box cyan">🔍</div>
        </div>
        <div class="metric-value-row">
          <span class="metric-number">{{ number_format($totalScans) }}</span>
          <span class="metric-badge-trend positive">↑ 100% Monitored</span>
        </div>
        <div class="metric-footer-text">
          <span class="text-safe-dot">●</span> {{ $safeScans }} Clean &bull; <span class="text-threat-dot">●</span> {{ $threatsBlocked }} Threats Intercepted
        </div>
        <div class="metric-progress-track">
          @php
            $safePercent = $totalScans > 0 ? round(($safeScans / $totalScans) * 100) : 100;
          @endphp
          <div class="metric-progress-fill cyan" style="width: {{ $safePercent }}%;"></div>
        </div>
      </div>

      <!-- Metric 2: Threats Neutralized -->
      <div class="metric-card red-glow">
        <div class="metric-header">
          <span class="metric-label">Threats Intercepted</span>
          <div class="metric-icon-box red">🛡️</div>
        </div>
        <div class="metric-value-row">
          <span class="metric-number text-threat">{{ number_format($threatsBlocked) }}</span>
          <span class="metric-badge-trend danger">High Risk</span>
        </div>
        <div class="metric-footer-text">
          Zero-Day Phishing & Malware Neutralized
        </div>
        <div class="metric-progress-track">
          @php
            $threatPercent = $totalScans > 0 ? min(100, round(($threatsBlocked / $totalScans) * 100)) : 0;
          @endphp
          <div class="metric-progress-fill red" style="width: {{ max(6, $threatPercent) }}%;"></div>
        </div>
      </div>

      <!-- Metric 3: Security Score Radial Ring -->
      <div class="metric-card emerald-glow">
        <div class="metric-header">
          <span class="metric-label">Security Health Posture</span>
          <div class="metric-icon-box emerald">⚡</div>
        </div>
        <div class="metric-score-container">
          <div class="score-ring-wrap">
            <svg class="score-ring-svg" viewBox="0 0 36 36">
              <path class="ring-bg"
                d="M18 2.0845
                  a 15.9155 15.9155 0 0 1 0 31.831
                  a 15.9155 15.9155 0 0 1 0 -31.831"
              />
              <path class="ring-fill"
                stroke-dasharray="{{ $securityScore['score'] ?? 95 }}, 100"
                style="stroke: {{ $securityScore['color'] ?? '#10b981' }};"
                d="M18 2.0845
                  a 15.9155 15.9155 0 0 1 0 31.831
                  a 15.9155 15.9155 0 0 1 0 -31.831"
              />
            </svg>
            <div class="score-ring-inner">
              <span class="score-number">{{ $securityScore['score'] ?? 95 }}</span>
            </div>
          </div>
          <div class="score-info">
            <div class="score-grade-badge" style="background: rgba(16,185,129,0.15); color: {{ $securityScore['color'] ?? '#10b981' }}; border: 1px solid {{ $securityScore['color'] ?? '#10b981' }}40;">
              GRADE {{ $securityScore['grade'] ?? 'A' }}
            </div>
            <a href="{{ route('security.score') }}" class="score-link">
              View Breakdown →
            </a>
          </div>
        </div>
      </div>

      <!-- Metric 4: API Access & Quota -->
      <div class="metric-card indigo-glow">
        <div class="metric-header">
          <span class="metric-label">API Key & Entitlement</span>
          <div class="metric-icon-box indigo">🔑</div>
        </div>
        <div class="api-key-display-box">
          @if($user->api_key)
            <code class="api-key-code" id="apiKeyText">{{ substr($user->api_key, 0, 16) }}••••••••</code>
            <button type="button" class="btn-copy-key" id="copyApiKeyBtn" data-key="{{ $user->api_key }}" title="Copy API Key">
              <span id="copyIcon">📋</span>
            </button>
          @else
            <span class="api-key-empty">Key Not Issued</span>
            <a href="{{ route('settings') }}" class="btn-generate-inline">Generate</a>
          @endif
        </div>
        <div class="quota-meta">
          <div class="quota-label-row">
            <span>Monthly Usage</span>
            <span>{{ $user->scans_used ?? 0 }} / {{ $user->scan_limit ?? 500 }}</span>
          </div>
          <div class="metric-progress-track">
            @php
              $limit = $user->scan_limit ?? 500;
              $used = $user->scans_used ?? 0;
              $quotaPercent = $limit > 0 ? min(100, round(($used / $limit) * 100)) : 0;
            @endphp
            <div class="metric-progress-fill indigo" style="width: {{ $quotaPercent }}%;"></div>
          </div>
        </div>
      </div>

    </div>

    <!-- Security Operations Capabilities Modules -->
    <div class="section-title-row">
      <h2 class="section-heading">Security Operations & Modules</h2>
      <span class="section-subtext">Direct access to intelligent threat forensics and perimeter settings</span>
    </div>

    <div class="capabilities-grid">

      <!-- Module 1: Threat Forensics & Reports -->
      <a href="{{ route('reports.index') }}" class="capability-card">
        <div class="capability-icon-wrap" style="background: rgba(99, 102, 241, 0.15); border-color: rgba(99, 102, 241, 0.35);">
          📑
        </div>
        <div class="capability-content">
          <div class="capability-title">Forensic Audit Reports</div>
          <div class="capability-desc">Evidence breakdown, risk metrics & PDF export</div>
        </div>
        <span class="card-arrow">→</span>
      </a>

      <!-- Module 2: AI Threat Copilot -->
      <a href="{{ route('ai.page') }}" class="capability-card">
        <div class="capability-icon-wrap" style="background: rgba(217, 70, 239, 0.15); border-color: rgba(217, 70, 239, 0.35);">
          🤖
        </div>
        <div class="capability-content">
          <div class="capability-title">AI Threat Copilot</div>
          <div class="capability-desc">Real-time scam analysis with Gemini Assistant</div>
        </div>
        <span class="card-arrow">→</span>
      </a>

      <!-- Module 3: Domain Perimeter Firewall -->
      <a href="{{ route('block_list') }}" class="capability-card">
        <div class="capability-icon-wrap" style="background: rgba(239, 68, 68, 0.15); border-color: rgba(239, 68, 68, 0.35);">
          🛡️
        </div>
        <div class="capability-content">
          <div class="capability-title">Perimeter Rules & Blocklist</div>
          <div class="capability-desc">Custom domain blocking and whitelist allow-rules</div>
        </div>
        <span class="card-arrow">→</span>
      </a>

      <!-- Module 4: Browser Guard Extension -->
      <a href="{{ route('extension.setup') }}" class="capability-card">
        <div class="capability-icon-wrap" style="background: rgba(16, 185, 129, 0.15); border-color: rgba(16, 185, 129, 0.35);">
          🧩
        </div>
        <div class="capability-content">
          <div class="capability-title">Chrome Shield Extension</div>
          <div class="capability-desc">Real-time browser-level protection and sync</div>
        </div>
        <span class="card-arrow">→</span>
      </a>

      <!-- Module 5: Security Score Posture -->
      <a href="{{ route('security.score') }}" class="capability-card">
        <div class="capability-icon-wrap" style="background: rgba(14, 165, 233, 0.15); border-color: rgba(14, 165, 233, 0.35);">
          ⚡
        </div>
        <div class="capability-content">
          <div class="capability-title">Posture Breakdown</div>
          <div class="capability-desc">2FA posture, breach status, and recommendations</div>
        </div>
        <span class="card-arrow">→</span>
      </a>

      <!-- Module 6: Subscription & Upgrades -->
      <a href="{{ route('subscription') }}" class="capability-card">
        <div class="capability-icon-wrap" style="background: rgba(245, 158, 11, 0.15); border-color: rgba(245, 158, 11, 0.35);">
          💳
        </div>
        <div class="capability-content">
          <div class="capability-title">Subscription & Quotas</div>
          <div class="capability-desc">Manage plan entitlements, limits & invoicing</div>
        </div>
        <span class="card-arrow">→</span>
      </a>

    </div>

    <!-- Recent Threat Intelligence Scans Table -->
    <div class="threat-table-card">
      <div class="table-header-row">
        <div>
          <h3 class="table-heading">Recent Threat Intelligence Scans</h3>
          <p class="table-subheading">Live log of URLs, domains, and artifacts evaluated by the neural inspection engine</p>
        </div>
        <div class="table-header-actions">
          <input
            type="text"
            id="tableFilterInput"
            class="table-search-input"
            placeholder="Filter scans by target or risk..."
          />
          <a href="{{ route('history') }}" class="btn-view-all">
            View All Scans →
          </a>
        </div>
      </div>

      @if($recentScans->isEmpty())
        <div class="empty-state-box">
          <div class="empty-icon-wrap">🛡️</div>
          <h4 class="empty-title">No Scans Recorded Yet</h4>
          <p class="empty-desc">Your command center is ready. Paste a URL in the Quick Scanner above or explore the Security Suite.</p>
          <a href="{{ route('tools.home') }}" class="btn-empty-action">
            ⚡ Launch First Scan
          </a>
        </div>
      @else
        <div class="table-responsive">
          <table class="cyber-table" id="recentScansTable">
            <thead>
              <tr>
                <th>Target Content</th>
                <th>Classification</th>
                <th>Risk Score</th>
                <th>Timestamp</th>
                <th style="text-align: right;">Action</th>
              </tr>
            </thead>
            <tbody>
              @foreach($recentScans as $scan)
                <tr class="scan-row" data-content="{{ strtolower($scan->content) }}" data-risk="{{ strtolower($scan->risk_level) }}">
                  <td>
                    <div class="target-cell">
                      <span class="target-protocol-icon">
                        @if(str_starts_with($scan->content, 'https'))
                          🔒
                        @else
                          🌐
                        @endif
                      </span>
                      <span class="target-text" title="{{ $scan->content }}">
                        {{ Str::limit($scan->content, 54) }}
                      </span>
                    </div>
                  </td>
                  <td>
                    @php
                      $risk = strtolower($scan->risk_level);
                    @endphp
                    @if($risk === 'high' || $risk === 'malicious')
                      <span class="threat-pill threat-danger">
                        <span class="pill-dot red"></span> DANGER
                      </span>
                    @elseif($risk === 'medium' || $risk === 'suspicious')
                      <span class="threat-pill threat-warn">
                        <span class="pill-dot yellow"></span> SUSPICIOUS
                      </span>
                    @else
                      <span class="threat-pill threat-safe">
                        <span class="pill-dot green"></span> SAFE
                      </span>
                    @endif
                  </td>
                  <td>
                    <div class="score-cell">
                      <span class="score-val">{{ $scan->risk_score }}</span>
                      <span class="score-max">/ 100</span>
                      <div class="mini-score-bar">
                        <div class="mini-score-fill {{ $risk === 'high' ? 'red' : ($risk === 'medium' ? 'yellow' : 'green') }}" style="width: {{ $scan->risk_score }}%;"></div>
                      </div>
                    </div>
                  </td>
                  <td class="text-timestamp">
                    {{ $scan->created_at->diffForHumans() }}
                  </td>
                  <td style="text-align: right;">
                    <a href="{{ route('reports.show', $scan->id) }}" class="btn-table-action">
                      Report →
                    </a>
                  </td>
                </tr>
              @endforeach
            </tbody>
          </table>
        </div>
      @endif
    </div>

  </main>
</div>

<!-- Scoped Cyber Command Center Stylesheet -->
<style>
  /* Layout Architecture */
  .command-center-layout {
    display: flex;
    min-height: calc(100vh - 72px);
    background: #060814;
    color: #f8fafc;
    font-family: var(--font-sans, 'Inter', -apple-system, sans-serif);
  }

  .command-center-main {
    flex: 1;
    padding: 2.25rem 2.5rem;
    max-width: 1540px;
    margin: 0 auto;
    width: 100%;
    box-sizing: border-box;
  }

  /* Hero Section */
  .dashboard-hero {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    flex-wrap: wrap;
    gap: 1.5rem;
    margin-bottom: 2rem;
  }

  .hero-badge-row {
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    margin-bottom: 0.75rem;
  }

  .pulse-indicator {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    background: rgba(16, 185, 129, 0.12);
    border: 1px solid rgba(16, 185, 129, 0.35);
    padding: 4px 12px;
    border-radius: 9999px;
  }

  .pulse-dot {
    width: 8px;
    height: 8px;
    background: #10b981;
    border-radius: 50%;
    box-shadow: 0 0 10px #10b981;
    animation: pulseGlow 1.8s infinite;
  }

  .pulse-text {
    font-size: 0.75rem;
    font-weight: 800;
    color: #34d399;
    letter-spacing: 0.05em;
  }

  .tier-badge {
    background: rgba(99, 102, 241, 0.15);
    border: 1px solid rgba(99, 102, 241, 0.35);
    color: #a5b4fc;
    font-size: 0.75rem;
    font-weight: 800;
    padding: 4px 12px;
    border-radius: 9999px;
    letter-spacing: 0.04em;
  }

  .latency-badge {
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid rgba(255, 255, 255, 0.1);
    color: #94a3b8;
    font-size: 0.75rem;
    font-weight: 600;
    padding: 4px 10px;
    border-radius: 9999px;
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .dot-green {
    width: 6px;
    height: 6px;
    background: #10b981;
    border-radius: 50%;
  }

  .hero-title {
    font-family: var(--font-display, 'Plus Jakarta Sans', sans-serif);
    font-size: 2.35rem;
    font-weight: 900;
    color: #ffffff;
    margin: 0 0 0.35rem 0;
    letter-spacing: -0.02em;
  }

  .hero-subtitle {
    color: #94a3b8;
    font-size: 0.985rem;
    margin: 0;
  }

  .text-highlight {
    color: #e2e8f0;
  }

  .hero-actions {
    display: flex;
    gap: 12px;
    align-items: center;
  }

  .btn-hero-primary {
    background: linear-gradient(135deg, #6366f1 0%, #a855f7 50%, #ec4899 100%);
    color: #fff;
    padding: 0.8rem 1.6rem;
    border-radius: 12px;
    font-weight: 800;
    font-size: 0.925rem;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    gap: 8px;
    box-shadow: 0 6px 24px rgba(99, 102, 241, 0.4);
    transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
    border: 1px solid rgba(255, 255, 255, 0.15);
  }

  .btn-hero-primary:hover {
    transform: translateY(-2px);
    box-shadow: 0 10px 32px rgba(168, 85, 247, 0.55);
    filter: brightness(1.08);
  }

  .btn-hero-secondary {
    background: rgba(30, 41, 59, 0.7);
    color: #e2e8f0;
    border: 1px solid rgba(99, 102, 241, 0.25);
    padding: 0.8rem 1.4rem;
    border-radius: 12px;
    font-weight: 700;
    font-size: 0.925rem;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
    gap: 8px;
    backdrop-filter: blur(12px);
    transition: all 0.2s ease;
  }

  .btn-hero-secondary:hover {
    background: rgba(51, 65, 85, 0.9);
    border-color: rgba(99, 102, 241, 0.5);
    color: #fff;
    transform: translateY(-2px);
  }

  /* Threat Alert Banner */
  .security-alert-banner {
    background: linear-gradient(90deg, rgba(239, 68, 68, 0.15) 0%, rgba(15, 23, 42, 0.9) 100%);
    border: 1px solid rgba(239, 68, 68, 0.4);
    border-radius: 16px;
    padding: 1.15rem 1.6rem;
    margin-bottom: 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 1rem;
    box-shadow: 0 8px 24px rgba(239, 68, 68, 0.15);
  }

  .alert-content {
    display: flex;
    align-items: center;
    gap: 14px;
  }

  .alert-icon-wrap {
    font-size: 1.6rem;
    background: rgba(239, 68, 68, 0.2);
    width: 44px;
    height: 44px;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    border: 1px solid rgba(239, 68, 68, 0.4);
  }

  .alert-title {
    font-weight: 800;
    color: #fff;
    font-size: 0.975rem;
  }

  .alert-desc {
    color: #cbd5e1;
    font-size: 0.85rem;
    margin-top: 2px;
  }

  .alert-action-btn {
    background: rgba(239, 68, 68, 0.25);
    color: #fca5a5;
    border: 1px solid rgba(239, 68, 68, 0.5);
    padding: 0.6rem 1.2rem;
    border-radius: 10px;
    font-size: 0.85rem;
    font-weight: 700;
    text-decoration: none;
    transition: all 0.2s ease;
  }

  .alert-action-btn:hover {
    background: #ef4444;
    color: #fff;
  }

  /* Quick Scanner Hero Widget */
  .quick-scanner-card {
    background: radial-gradient(circle at top right, rgba(99, 102, 241, 0.12) 0%, rgba(15, 23, 42, 0.85) 60%);
    border: 1px solid rgba(99, 102, 241, 0.3);
    border-radius: 20px;
    padding: 1.75rem 2rem;
    margin-bottom: 2.5rem;
    box-shadow: 0 16px 40px rgba(0, 0, 0, 0.45);
    backdrop-filter: blur(20px);
    position: relative;
    overflow: hidden;
  }

  .quick-scanner-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 2px;
    background: linear-gradient(90deg, transparent, #6366f1, #a855f7, #ec4899, transparent);
  }

  .scanner-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 1rem;
    margin-bottom: 1.25rem;
  }

  .scanner-title-group {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .scanner-icon {
    font-size: 1.6rem;
    background: rgba(99, 102, 241, 0.2);
    border: 1px solid rgba(99, 102, 241, 0.4);
    width: 44px;
    height: 44px;
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .scanner-heading {
    color: #fff;
    font-size: 1.2rem;
    font-weight: 800;
    margin: 0;
  }

  .scanner-subheading {
    color: #94a3b8;
    font-size: 0.85rem;
    margin: 3px 0 0 0;
  }

  .scanner-layers-indicator {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
  }

  .layer-tag {
    background: rgba(30, 41, 59, 0.6);
    border: 1px solid rgba(255, 255, 255, 0.08);
    color: #cbd5e1;
    font-size: 0.72rem;
    font-weight: 700;
    padding: 3px 9px;
    border-radius: 6px;
    letter-spacing: 0.03em;
  }

  .quick-scanner-form {
    width: 100%;
  }

  .scanner-input-container {
    display: flex;
    align-items: center;
    background: rgba(10, 15, 30, 0.85);
    border: 1.5px solid rgba(99, 102, 241, 0.35);
    border-radius: 14px;
    padding: 4px 6px 4px 14px;
    transition: all 0.25s ease;
  }

  .scanner-input-container:focus-within {
    border-color: #818cf8;
    box-shadow: 0 0 24px rgba(99, 102, 241, 0.35);
  }

  .input-protocol-badge {
    color: #64748b;
    font-family: var(--font-mono, monospace);
    font-size: 0.9rem;
    font-weight: 700;
    margin-right: 6px;
    user-select: none;
  }

  .scanner-input {
    flex: 1;
    background: transparent;
    border: none;
    color: #fff;
    font-size: 0.985rem;
    outline: none;
    padding: 0.75rem 0.5rem;
    font-family: var(--font-sans, inherit);
  }

  .scanner-input::placeholder {
    color: #64748b;
  }

  .btn-clear-input {
    background: transparent;
    border: none;
    color: #64748b;
    font-size: 1rem;
    padding: 0 10px;
    cursor: pointer;
    transition: color 0.2s;
  }

  .btn-clear-input:hover {
    color: #cbd5e1;
  }

  .scanner-submit-btn {
    background: linear-gradient(135deg, #6366f1 0%, #a855f7 100%);
    color: #fff;
    border: none;
    padding: 0.75rem 1.6rem;
    border-radius: 10px;
    font-weight: 800;
    font-size: 0.9rem;
    cursor: pointer;
    box-shadow: 0 4px 16px rgba(99, 102, 241, 0.35);
    transition: all 0.2s ease;
    display: inline-flex;
    align-items: center;
    gap: 8px;
    white-space: nowrap;
  }

  .scanner-submit-btn:hover {
    filter: brightness(1.1);
    transform: translateY(-1px);
    box-shadow: 0 6px 20px rgba(168, 85, 247, 0.45);
  }

  .btn-spinner {
    width: 14px;
    height: 14px;
    border: 2px solid rgba(255, 255, 255, 0.3);
    border-top-color: #fff;
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
  }

  /* Dynamic Scan Results Box */
  .quick-scan-result {
    margin-top: 1.25rem;
    padding: 1.25rem;
    border-radius: 14px;
    background: rgba(10, 15, 30, 0.9);
    border: 1px solid rgba(255, 255, 255, 0.1);
    animation: fadeIn 0.3s ease;
  }

  /* Metrics Grid */
  .metrics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    gap: 1.5rem;
    margin-bottom: 2.75rem;
  }

  .metric-card {
    background: rgba(15, 23, 42, 0.75);
    backdrop-filter: blur(20px);
    border-radius: 18px;
    border: 1px solid rgba(255, 255, 255, 0.08);
    padding: 1.6rem;
    transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
    box-shadow: 0 8px 30px rgba(0, 0, 0, 0.4);
    display: flex;
    flex-direction: column;
    justify-content: space-between;
  }

  .metric-card:hover {
    transform: translateY(-3px);
  }

  .metric-card.cyan-glow:hover {
    border-color: rgba(6, 182, 212, 0.4);
    box-shadow: 0 12px 35px rgba(6, 182, 212, 0.18);
  }

  .metric-card.red-glow:hover {
    border-color: rgba(239, 68, 68, 0.4);
    box-shadow: 0 12px 35px rgba(239, 68, 68, 0.18);
  }

  .metric-card.emerald-glow:hover {
    border-color: rgba(16, 185, 129, 0.4);
    box-shadow: 0 12px 35px rgba(16, 185, 129, 0.18);
  }

  .metric-card.indigo-glow:hover {
    border-color: rgba(99, 102, 241, 0.4);
    box-shadow: 0 12px 35px rgba(99, 102, 241, 0.18);
  }

  .metric-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.85rem;
  }

  .metric-label {
    font-size: 0.85rem;
    font-weight: 700;
    color: #94a3b8;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .metric-icon-box {
    width: 36px;
    height: 36px;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.15rem;
  }

  .metric-icon-box.cyan {
    background: rgba(6, 182, 212, 0.15);
    border: 1px solid rgba(6, 182, 212, 0.3);
  }

  .metric-icon-box.red {
    background: rgba(239, 68, 68, 0.15);
    border: 1px solid rgba(239, 68, 68, 0.3);
  }

  .metric-icon-box.emerald {
    background: rgba(16, 185, 129, 0.15);
    border: 1px solid rgba(16, 185, 129, 0.3);
  }

  .metric-icon-box.indigo {
    background: rgba(99, 102, 241, 0.15);
    border: 1px solid rgba(99, 102, 241, 0.3);
  }

  .metric-value-row {
    display: flex;
    align-items: baseline;
    gap: 10px;
    margin-bottom: 0.5rem;
  }

  .metric-number {
    font-size: 2.25rem;
    font-weight: 900;
    color: #fff;
    letter-spacing: -0.03em;
    line-height: 1.1;
  }

  .text-threat {
    color: #ef4444;
  }

  .metric-badge-trend {
    font-size: 0.72rem;
    font-weight: 800;
    padding: 2px 8px;
    border-radius: 9999px;
  }

  .metric-badge-trend.positive {
    background: rgba(16, 185, 129, 0.15);
    color: #34d399;
    border: 1px solid rgba(16, 185, 129, 0.3);
  }

  .metric-badge-trend.danger {
    background: rgba(239, 68, 68, 0.15);
    color: #fca5a5;
    border: 1px solid rgba(239, 68, 68, 0.3);
  }

  .metric-footer-text {
    font-size: 0.8rem;
    color: #94a3b8;
    margin-bottom: 0.85rem;
  }

  .text-safe-dot { color: #10b981; }
  .text-threat-dot { color: #ef4444; }

  .metric-progress-track {
    width: 100%;
    height: 6px;
    background: rgba(255, 255, 255, 0.06);
    border-radius: 9999px;
    overflow: hidden;
  }

  .metric-progress-fill {
    height: 100%;
    border-radius: 9999px;
  }

  .metric-progress-fill.cyan { background: linear-gradient(90deg, #06b6d4, #3b82f6); }
  .metric-progress-fill.red { background: linear-gradient(90deg, #f97316, #ef4444); }
  .metric-progress-fill.indigo { background: linear-gradient(90deg, #6366f1, #a855f7); }

  /* Radial Score Gauge Card */
  .metric-score-container {
    display: flex;
    align-items: center;
    gap: 1.25rem;
    margin-top: 0.25rem;
  }

  .score-ring-wrap {
    position: relative;
    width: 72px;
    height: 72px;
    flex-shrink: 0;
  }

  .score-ring-svg {
    width: 100%;
    height: 100%;
    transform: rotate(-90deg);
  }

  .ring-bg {
    fill: none;
    stroke: rgba(255, 255, 255, 0.08);
    stroke-width: 3.5;
  }

  .ring-fill {
    fill: none;
    stroke-width: 3.5;
    stroke-linecap: round;
    transition: stroke-dasharray 0.8s ease;
  }

  .score-ring-inner {
    position: absolute;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .score-number {
    font-size: 1.35rem;
    font-weight: 900;
    color: #fff;
  }

  .score-info {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .score-grade-badge {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 6px;
    font-size: 0.75rem;
    font-weight: 800;
    letter-spacing: 0.05em;
  }

  .score-link {
    color: #38bdf8;
    font-size: 0.8rem;
    font-weight: 700;
    text-decoration: none;
  }

  .score-link:hover {
    text-decoration: underline;
  }

  /* API Key display box */
  .api-key-display-box {
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: rgba(10, 15, 30, 0.7);
    border: 1px solid rgba(99, 102, 241, 0.25);
    border-radius: 10px;
    padding: 6px 10px;
    margin-bottom: 0.85rem;
  }

  .api-key-code {
    font-family: var(--font-mono, monospace);
    font-size: 0.85rem;
    color: #a5b4fc;
    letter-spacing: 0.05em;
  }

  .btn-copy-key {
    background: transparent;
    border: none;
    color: #94a3b8;
    cursor: pointer;
    font-size: 0.95rem;
    padding: 2px 6px;
    transition: color 0.2s;
  }

  .btn-copy-key:hover {
    color: #fff;
  }

  .api-key-empty {
    font-size: 0.8rem;
    color: #64748b;
  }

  .btn-generate-inline {
    font-size: 0.75rem;
    color: #818cf8;
    font-weight: 700;
    text-decoration: none;
  }

  .quota-meta {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .quota-label-row {
    display: flex;
    justify-content: space-between;
    font-size: 0.75rem;
    color: #94a3b8;
    font-weight: 600;
  }

  /* Section Title */
  .section-title-row {
    margin-bottom: 1.25rem;
  }

  .section-heading {
    font-size: 1.35rem;
    font-weight: 800;
    color: #fff;
    margin: 0;
    letter-spacing: -0.01em;
  }

  .section-subtext {
    font-size: 0.85rem;
    color: #94a3b8;
  }

  /* Capabilities Grid */
  .capabilities-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 1.25rem;
    margin-bottom: 3rem;
  }

  .capability-card {
    background: rgba(15, 23, 42, 0.75);
    backdrop-filter: blur(16px);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 16px;
    padding: 1.25rem 1.4rem;
    text-decoration: none;
    display: flex;
    align-items: center;
    gap: 14px;
    transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
  }

  .capability-card:hover {
    background: rgba(22, 33, 62, 0.85);
    border-color: rgba(99, 102, 241, 0.4);
    transform: translateY(-2px);
    box-shadow: 0 10px 28px rgba(0, 0, 0, 0.4);
  }

  .capability-icon-wrap {
    width: 48px;
    height: 48px;
    border-radius: 14px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.5rem;
    border: 1px solid;
    flex-shrink: 0;
  }

  .capability-content {
    flex: 1;
    min-width: 0;
  }

  .capability-title {
    color: #fff;
    font-weight: 800;
    font-size: 0.95rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .capability-desc {
    color: #94a3b8;
    font-size: 0.785rem;
    margin-top: 2px;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .card-arrow {
    color: #64748b;
    font-size: 1.1rem;
    transition: all 0.2s;
  }

  .capability-card:hover .card-arrow {
    color: #a5b4fc;
    transform: translateX(4px);
  }

  /* Recent Scans Table Section */
  .threat-table-card {
    background: rgba(15, 23, 42, 0.85);
    backdrop-filter: blur(24px);
    border-radius: 20px;
    border: 1px solid rgba(99, 102, 241, 0.22);
    padding: 2rem;
    box-shadow: 0 16px 48px rgba(0, 0, 0, 0.5);
  }

  .table-header-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 1.25rem;
    margin-bottom: 1.5rem;
  }

  .table-heading {
    color: #fff;
    font-size: 1.35rem;
    font-weight: 800;
    margin: 0;
  }

  .table-subheading {
    color: #94a3b8;
    font-size: 0.85rem;
    margin: 3px 0 0 0;
  }

  .table-header-actions {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .table-search-input {
    background: rgba(10, 15, 30, 0.7);
    border: 1px solid rgba(255, 255, 255, 0.12);
    color: #fff;
    padding: 0.55rem 1rem;
    border-radius: 10px;
    font-size: 0.85rem;
    outline: none;
    width: 240px;
    transition: all 0.2s;
  }

  .table-search-input:focus {
    border-color: #6366f1;
    box-shadow: 0 0 16px rgba(99, 102, 241, 0.25);
  }

  .btn-view-all {
    color: #a5b4fc;
    font-size: 0.875rem;
    font-weight: 700;
    text-decoration: none;
    background: rgba(99, 102, 241, 0.12);
    border: 1px solid rgba(99, 102, 241, 0.3);
    padding: 0.55rem 1.1rem;
    border-radius: 10px;
    transition: all 0.2s;
    white-space: nowrap;
  }

  .btn-view-all:hover {
    background: rgba(99, 102, 241, 0.25);
    color: #fff;
  }

  /* Table Styles */
  .table-responsive {
    overflow-x: auto;
  }

  .cyber-table {
    width: 100%;
    border-collapse: collapse;
    text-align: left;
    color: #cbd5e1;
    font-size: 0.9rem;
  }

  .cyber-table thead tr {
    border-bottom: 1px solid rgba(99, 102, 241, 0.2);
    color: #94a3b8;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .cyber-table th {
    padding: 1rem 1.25rem;
    font-weight: 700;
  }

  .cyber-table tbody tr {
    border-bottom: 1px solid rgba(255, 255, 255, 0.04);
    transition: background 0.2s ease;
  }

  .cyber-table tbody tr:hover {
    background: rgba(99, 102, 241, 0.07);
  }

  .cyber-table td {
    padding: 1.1rem 1.25rem;
  }

  .target-cell {
    display: flex;
    align-items: center;
    gap: 10px;
  }

  .target-protocol-icon {
    font-size: 1rem;
    opacity: 0.8;
  }

  .target-text {
    font-weight: 600;
    color: #fff;
    word-break: break-all;
    font-family: var(--font-mono, monospace);
    font-size: 0.885rem;
  }

  /* Threat Pills */
  .threat-pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    border-radius: 9999px;
    font-size: 0.72rem;
    font-weight: 800;
    letter-spacing: 0.04em;
    text-transform: uppercase;
  }

  .threat-pill.threat-danger {
    background: rgba(239, 68, 68, 0.18);
    color: #ef4444;
    border: 1px solid rgba(239, 68, 68, 0.45);
  }

  .threat-pill.threat-warn {
    background: rgba(245, 158, 11, 0.18);
    color: #f59e0b;
    border: 1px solid rgba(245, 158, 11, 0.45);
  }

  .threat-pill.threat-safe {
    background: rgba(16, 185, 129, 0.18);
    color: #10b981;
    border: 1px solid rgba(16, 185, 129, 0.45);
  }

  .pill-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
  }

  .pill-dot.red { background: #ef4444; box-shadow: 0 0 6px #ef4444; }
  .pill-dot.yellow { background: #f59e0b; box-shadow: 0 0 6px #f59e0b; }
  .pill-dot.green { background: #10b981; box-shadow: 0 0 6px #10b981; }

  /* Score cell */
  .score-cell {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .score-val {
    font-weight: 800;
    color: #fff;
  }

  .score-max {
    font-size: 0.75rem;
    color: #64748b;
  }

  .mini-score-bar {
    width: 48px;
    height: 4px;
    background: rgba(255, 255, 255, 0.08);
    border-radius: 9999px;
    overflow: hidden;
    margin-left: 6px;
  }

  .mini-score-fill {
    height: 100%;
    border-radius: 9999px;
  }

  .mini-score-fill.red { background: #ef4444; }
  .mini-score-fill.yellow { background: #f59e0b; }
  .mini-score-fill.green { background: #10b981; }

  .text-timestamp {
    color: #94a3b8;
    font-size: 0.85rem;
  }

  .btn-table-action {
    display: inline-block;
    color: #a5b4fc;
    font-size: 0.85rem;
    font-weight: 700;
    text-decoration: none;
    background: rgba(99, 102, 241, 0.15);
    border: 1px solid rgba(99, 102, 241, 0.35);
    padding: 6px 14px;
    border-radius: 8px;
    transition: all 0.2s;
  }

  .btn-table-action:hover {
    background: #6366f1;
    color: #fff;
    border-color: #6366f1;
  }

  /* Empty state */
  .empty-state-box {
    text-align: center;
    padding: 4rem 1.5rem;
  }

  .empty-icon-wrap {
    font-size: 3rem;
    margin-bottom: 1rem;
    opacity: 0.8;
  }

  .empty-title {
    font-size: 1.25rem;
    font-weight: 800;
    color: #fff;
    margin: 0 0 0.5rem 0;
  }

  .empty-desc {
    color: #94a3b8;
    font-size: 0.95rem;
    max-width: 460px;
    margin: 0 auto 1.5rem auto;
  }

  .btn-empty-action {
    display: inline-block;
    background: linear-gradient(135deg, #6366f1, #a855f7);
    color: #fff;
    padding: 0.75rem 1.75rem;
    border-radius: 10px;
    font-weight: 800;
    text-decoration: none;
    box-shadow: 0 6px 20px rgba(99, 102, 241, 0.35);
    transition: all 0.2s;
  }

  .btn-empty-action:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 24px rgba(168, 85, 247, 0.45);
  }

  /* Animations */
  @keyframes pulseGlow {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.4; transform: scale(0.9); }
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  @keyframes fadeIn {
    from { opacity: 0; transform: translateY(-6px); }
    to { opacity: 1; transform: translateY(0); }
  }

  /* Responsive Breakpoints */
  @media (max-width: 900px) {
    .command-center-main {
      padding: 1.5rem;
    }
    .hero-title {
      font-size: 1.85rem;
    }
    .metrics-grid {
      grid-template-columns: 1fr;
    }
  }
</style>

<!-- Interactive Live Scripting -->
<script>
  document.addEventListener('DOMContentLoaded', () => {
    // 1. One-Click Copy API Key with Toast Feedback
    const copyBtn = document.getElementById('copyApiKeyBtn');
    if (copyBtn) {
      copyBtn.addEventListener('click', async () => {
        const key = copyBtn.getAttribute('data-key');
        if (!key) return;

        try {
          await navigator.clipboard.writeText(key);
          const icon = document.getElementById('copyIcon');
          icon.textContent = '✅';
          copyBtn.style.color = '#10b981';

          setTimeout(() => {
            icon.textContent = '📋';
            copyBtn.style.color = '';
          }, 2000);
        } catch (err) {
          console.error('Failed to copy API key', err);
        }
      });
    }

    // 2. Clear input button
    const clearBtn = document.getElementById('clearScanInput');
    const scanInput = document.getElementById('quickScanInput');
    if (clearBtn && scanInput) {
      clearBtn.addEventListener('click', () => {
        scanInput.value = '';
        scanInput.focus();
      });
    }

    // 3. Quick Real-Time Scan Submission via AJAX
    const scanForm = document.getElementById('quickScanForm');
    const resultBox = document.getElementById('quickScanResult');
    const submitBtn = document.getElementById('quickScanSubmitBtn');

    if (scanForm && scanInput && resultBox && submitBtn) {
      scanForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const targetUrl = scanInput.value.trim();
        if (!targetUrl) return;

        // UI state: Scanning
        const btnText = submitBtn.querySelector('.btn-text');
        const spinner = submitBtn.querySelector('.btn-spinner');
        btnText.textContent = 'Analyzing...';
        spinner.style.display = 'inline-block';
        submitBtn.disabled = true;

        resultBox.style.display = 'block';
        resultBox.innerHTML = `
          <div style="display: flex; align-items: center; gap: 12px; color: #a5b4fc;">
            <div class="btn-spinner" style="display: inline-block; width: 18px; height: 18px;"></div>
            <div>
              <div style="font-weight: 700; font-size: 0.95rem;">Evaluating Multi-Layer Threat Signatures...</div>
              <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 2px;">Extracting 50 URL features &bull; Querying XGBoost ML &bull; Validating Safe Browsing</div>
            </div>
          </div>
        `;

        try {
          const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
          const response = await fetch('/api/scan', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json',
              'X-CSRF-TOKEN': csrfToken || ''
            },
            body: JSON.stringify({ url: targetUrl })
          });

          const resData = await response.json();

          if (resData.success && resData.data) {
            const data = resData.data;
            const isDanger = data.risk_level === 'high' || data.level === 'MALICIOUS';
            const isWarn = data.risk_level === 'medium' || data.level === 'SUSPICIOUS';
            const badgeColor = isDanger ? '#ef4444' : (isWarn ? '#f59e0b' : '#10b981');
            const badgeBg = isDanger ? 'rgba(239,68,68,0.2)' : (isWarn ? 'rgba(245,158,11,0.2)' : 'rgba(16,185,129,0.2)');
            const borderCol = isDanger ? 'rgba(239,68,68,0.45)' : (isWarn ? 'rgba(245,158,11,0.45)' : 'rgba(16,185,129,0.45)');
            const levelLabel = isDanger ? 'MALICIOUS / HIGH RISK' : (isWarn ? 'SUSPICIOUS RISK' : 'CLEAN & SAFE');

            resultBox.innerHTML = `
              <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 1rem; border-bottom: 1px solid rgba(255,255,255,0.08); padding-bottom: 0.85rem; margin-bottom: 0.85rem;">
                <div style="display: flex; align-items: center; gap: 10px;">
                  <span style="background: ${badgeBg}; color: ${badgeColor}; border: 1px solid ${borderCol}; padding: 4px 12px; border-radius: 9999px; font-weight: 800; font-size: 0.78rem;">
                    ${levelLabel}
                  </span>
                  <span style="font-weight: 700; color: #fff; font-size: 0.95rem;">Risk Score: ${data.risk_score ?? data.score ?? 0} / 100</span>
                </div>
                <div>
                  ${data.scan_id ? `<a href="/reports/${data.scan_id}" style="color: #a5b4fc; font-weight: 700; font-size: 0.85rem; text-decoration: none;">View Detailed Forensics →</a>` : ''}
                </div>
              </div>
              <div style="color: #cbd5e1; font-size: 0.885rem; line-height: 1.5;">
                ${data.explanation || data.recommended_action || 'Inspection completed successfully across all intelligence layers.'}
              </div>
            `;
          } else {
            resultBox.innerHTML = `
              <div style="color: #ef4444; font-weight: 700;">
                Inspection Notice: ${resData.message || 'Unable to scan target.'}
              </div>
            `;
          }
        } catch (err) {
          resultBox.innerHTML = `
            <div style="color: #ef4444; font-weight: 600;">
              Connection Error: Could not reach the inspection engine. Please verify the backend service is operational.
            </div>
          `;
        } finally {
          btnText.textContent = 'Inspect Target';
          spinner.style.display = 'none';
          submitBtn.disabled = false;
        }
      });
    }

    // 4. Live Table Search Filter
    const filterInput = document.getElementById('tableFilterInput');
    const tableRows = document.querySelectorAll('.scan-row');
    if (filterInput && tableRows.length > 0) {
      filterInput.addEventListener('input', (e) => {
        const query = e.target.value.toLowerCase().trim();
        tableRows.forEach(row => {
          const content = row.getAttribute('data-content') || '';
          const risk = row.getAttribute('data-risk') || '';
          if (content.includes(query) || risk.includes(query)) {
            row.style.display = '';
          } else {
            row.style.display = 'none';
          }
        });
      });
    }
  });
</script>
@endsection
