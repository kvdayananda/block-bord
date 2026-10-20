@extends('layouts.app')

@section('title', 'Threat & Scam Queue — Admin Console — Block Bord AI')

@section('content')
<div style="display: flex; min-height: calc(100vh - 70px); background: #060814;">
  <x-sidebar />

  <main style="flex: 1; padding: 2.5rem; background: #060814; color: #fff;">

    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; flex-wrap: wrap; gap: 1rem;">
      <div>
        <h1 style="font-size: 2.25rem; font-weight: 900; color: #fff; margin: 0 0 4px 0;">Threat & Scam Queue</h1>
        <p style="color: #94a3b8; font-size: 0.95rem; margin: 0;">Review crowdsourced phishing and scam reports submitted by users and the Chrome Extension.</p>
      </div>
    </div>

    <!-- Admin Nav Tabs -->
    <x-admin-nav />

    <!-- Reports Table -->
    <div style="background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(20px); border-radius: 20px; border: 1px solid rgba(245, 158, 11, 0.25); padding: 1.75rem; box-shadow: 0 12px 32px rgba(0,0,0,0.5);">
      <h3 style="font-size: 1.25rem; font-weight: 800; color: #fff; margin-bottom: 1.25rem;">
        User Flagged Domains & Scam Links
      </h3>

      @if($reports->isEmpty())
        <div style="text-align: center; padding: 3rem 1rem; color: #94a3b8;">
          <div style="font-size: 2.5rem; margin-bottom: 1rem;">🛡️</div>
          <p style="font-size: 1.1rem; margin-bottom: 0.5rem;">No user reports in queue.</p>
        </div>
      @else
        <div style="overflow-x: auto;">
          <table style="width: 100%; border-collapse: collapse; text-align: left; color: #cbd5e1;">
            <thead>
              <tr style="border-bottom: 1px solid rgba(245, 158, 11, 0.2); color: #94a3b8; font-size: 0.825rem; text-transform: uppercase;">
                <th style="padding: 1rem;">ID</th>
                <th style="padding: 1rem;">Reported Target</th>
                <th style="padding: 1rem;">User Description</th>
                <th style="padding: 1rem;">Reported By</th>
                <th style="padding: 1rem;">Status</th>
                <th style="padding: 1rem;">Date</th>
                <th style="padding: 1rem; text-align: right;">Moderation Action</th>
              </tr>
            </thead>
            <tbody>
              @foreach($reports as $rep)
                <tr style="border-bottom: 1px solid rgba(255,255,255,0.05); transition: background 0.2s;" onmouseover="this.style.background='rgba(245,158,11,0.05)'" onmouseout="this.style.background='transparent'">
                  <td style="padding: 1rem; font-family: var(--font-mono, monospace); color: #64748b;">#{{ $rep->id }}</td>
                  <td style="padding: 1rem; font-weight: 700; color: #fff; word-break: break-all; max-width: 260px;">
                    {{ $rep->reported_url }}
                  </td>
                  <td style="padding: 1rem; color: #cbd5e1; font-size: 0.9rem;">
                    {{ $rep->description ?: 'Flagged via extension' }}
                  </td>
                  <td style="padding: 1rem; color: #94a3b8; font-size: 0.85rem;">
                    {{ $rep->user ? $rep->user->username : 'Anonymous' }}
                  </td>
                  <td style="padding: 1rem;">
                    <span style="padding: 0.3rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 800; text-transform: uppercase; background: {{ $rep->status === 'pending' ? 'rgba(245, 158, 11, 0.15)' : ($rep->status === 'resolved' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(255,255,255,0.05)') }}; color: {{ $rep->status === 'pending' ? '#f59e0b' : ($rep->status === 'resolved' ? '#ef4444' : '#94a3b8') }}; border: 1px solid {{ $rep->status === 'pending' ? 'rgba(245, 158, 11, 0.3)' : ($rep->status === 'resolved' ? 'rgba(239, 68, 68, 0.3)' : 'rgba(255,255,255,0.1)') }};">
                      {{ $rep->status }}
                    </span>
                  </td>
                  <td style="padding: 1rem; color: #64748b; font-size: 0.825rem;">{{ $rep->created_at->diffForHumans() }}</td>
                  <td style="padding: 1rem; text-align: right;">
                    @if($rep->status === 'pending')
                      <div style="display: inline-flex; gap: 8px;">
                        <!-- Blacklist & Resolve -->
                        <form method="POST" action="{{ route('admin.threats.resolve', $rep->id) }}">
                          @csrf
                          <input type="hidden" name="action" value="blacklist">
                          <button type="submit" style="background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); padding: 4px 10px; border-radius: 6px; font-size: 0.75rem; font-weight: 800; cursor: pointer;">
                            🚫 Blacklist
                          </button>
                        </form>

                        <!-- Dismiss -->
                        <form method="POST" action="{{ route('admin.threats.resolve', $rep->id) }}">
                          @csrf
                          <input type="hidden" name="action" value="dismiss">
                          <button type="submit" style="background: rgba(255,255,255,0.06); color: #94a3b8; border: 1px solid rgba(255,255,255,0.1); padding: 4px 8px; border-radius: 6px; font-size: 0.75rem; font-weight: 700; cursor: pointer;">
                            Dismiss
                          </button>
                        </form>
                      </div>
                    @else
                      <span style="color: #64748b; font-size: 0.8rem;">Processed</span>
                    @endif
                  </td>
                </tr>
              @endforeach
            </tbody>
          </table>
        </div>

        <div style="margin-top: 1.5rem;">
          {{ $reports->links() }}
        </div>
      @endif
    </div>

  </main>
</div>
@endsection
