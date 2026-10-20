@extends('layouts.app')

@section('title', 'System Logs & Diagnostics — Admin Console — Block Bord AI')

@section('content')
<div style="display: flex; min-height: calc(100vh - 70px); background: #060814;">
  <x-sidebar />

  <main style="flex: 1; padding: 2.5rem; background: #060814; color: #fff;">

    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; flex-wrap: wrap; gap: 1rem;">
      <div>
        <h1 style="font-size: 2.25rem; font-weight: 900; color: #fff; margin: 0 0 4px 0;">System Audit Logs & Environment</h1>
        <p style="color: #94a3b8; font-size: 0.95rem; margin: 0;">Comprehensive administrative audit trail, infrastructure status, and cache management.</p>
      </div>

      <div>
        <form method="POST" action="{{ route('admin.clear-cache') }}">
          @csrf
          <button type="submit" style="background: linear-gradient(135deg, #6366f1, #d946ef); color: #fff; padding: 0.75rem 1.4rem; border-radius: 10px; font-weight: 800; font-size: 0.875rem; border: none; cursor: pointer; box-shadow: 0 4px 15px rgba(99,102,241,0.35);">
            ⚡ Flush Application & View Cache
          </button>
        </form>
      </div>
    </div>

    <!-- Admin Nav Tabs -->
    <x-admin-nav />

    <!-- Infrastructure Environment Grid -->
    <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(99, 102, 241, 0.2); border-radius: 20px; padding: 1.75rem; margin-bottom: 2.5rem;">
      <h3 style="font-size: 1.15rem; font-weight: 800; color: #fff; margin: 0 0 1.25rem 0;">
        Infrastructure Environment & Stack Telemetry
      </h3>
      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.25rem;">
        <div style="background: #060814; padding: 1rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.06);">
          <span style="color: #64748b; font-size: 0.8rem; font-weight: 700; text-transform: uppercase;">PHP Runtime</span>
          <div style="font-size: 1.1rem; font-weight: 800; color: #fff; margin-top: 4px;">{{ $systemInfo['php_version'] }}</div>
        </div>
        <div style="background: #060814; padding: 1rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.06);">
          <span style="color: #64748b; font-size: 0.8rem; font-weight: 700; text-transform: uppercase;">Laravel Engine</span>
          <div style="font-size: 1.1rem; font-weight: 800; color: #a5b4fc; margin-top: 4px;">v{{ $systemInfo['laravel_version'] }}</div>
        </div>
        <div style="background: #060814; padding: 1rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.06);">
          <span style="color: #64748b; font-size: 0.8rem; font-weight: 700; text-transform: uppercase;">Database Connection</span>
          <div style="font-size: 1.1rem; font-weight: 800; color: #10b981; margin-top: 4px;">{{ strtoupper($systemInfo['database']) }} Active</div>
        </div>
        <div style="background: #060814; padding: 1rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.06);">
          <span style="color: #64748b; font-size: 0.8rem; font-weight: 700; text-transform: uppercase;">Environment Mode</span>
          <div style="font-size: 1.1rem; font-weight: 800; color: #f59e0b; margin-top: 4px;">{{ strtoupper($systemInfo['environment']) }}</div>
        </div>
      </div>
    </div>

    <!-- Audit Logs Table -->
    <div style="background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(20px); border-radius: 20px; border: 1px solid rgba(99, 102, 241, 0.2); padding: 1.5rem; box-shadow: 0 12px 32px rgba(0,0,0,0.5);">
      <h3 style="font-size: 1.2rem; font-weight: 800; color: #fff; margin-bottom: 1rem;">
        Security Audit Trail
      </h3>

      @if($auditLogs->isEmpty())
        <div style="text-align: center; padding: 3rem 1rem; color: #94a3b8;">
          No audit logs recorded yet.
        </div>
      @else
        <div style="overflow-x: auto;">
          <table style="width: 100%; border-collapse: collapse; text-align: left; color: #cbd5e1;">
            <thead>
              <tr style="border-bottom: 1px solid rgba(99, 102, 241, 0.2); color: #94a3b8; font-size: 0.825rem; text-transform: uppercase;">
                <th style="padding: 1rem;">Timestamp</th>
                <th style="padding: 1rem;">Action</th>
                <th style="padding: 1rem;">Admin User</th>
                <th style="padding: 1rem;">Operation Details</th>
                <th style="padding: 1rem; text-align: right;">IP Address</th>
              </tr>
            </thead>
            <tbody>
              @foreach($auditLogs as $log)
                <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
                  <td style="padding: 1rem; color: #64748b; font-size: 0.825rem; font-family: var(--font-mono, monospace);">
                    {{ $log->created_at->format('Y-m-d H:i:s') }}
                  </td>
                  <td style="padding: 1rem;">
                    <span style="font-weight: 800; color: #a5b4fc; font-size: 0.8rem; background: rgba(99,102,241,0.15); padding: 3px 8px; border-radius: 6px; font-family: var(--font-mono, monospace);">
                      {{ $log->action }}
                    </span>
                  </td>
                  <td style="padding: 1rem; color: #fff; font-weight: 700;">
                    {{ $log->user ? $log->user->username : 'System' }}
                  </td>
                  <td style="padding: 1rem; color: #cbd5e1; font-size: 0.875rem;">
                    {{ $log->details }}
                  </td>
                  <td style="padding: 1rem; color: #64748b; font-size: 0.825rem; text-align: right; font-family: var(--font-mono, monospace);">
                    {{ $log->ip_address ?: '127.0.0.1' }}
                  </td>
                </tr>
              @endforeach
            </tbody>
          </table>
        </div>

        <div style="margin-top: 1.5rem;">
          {{ $auditLogs->links() }}
        </div>
      @endif
    </div>

  </main>
</div>
@endsection
