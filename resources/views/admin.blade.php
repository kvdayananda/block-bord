@extends('layouts.app')

@section('title', 'Admin Intelligence Dashboard — Block Bord AI')

@section('content')
<div style="display: flex; min-height: calc(100vh - 70px); background: #060814;">
  <x-sidebar />

  <main style="flex: 1; padding: 2.5rem; background: #060814; color: #fff;">

    <!-- Header Section -->
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; flex-wrap: wrap; gap: 1rem;">
      <div>
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 6px;">
          <h1 style="font-size: 2.25rem; font-weight: 900; color: #fff; margin: 0;">Admin Intelligence Center</h1>
          <span style="background: rgba(239, 68, 68, 0.2); color: #ef4444; font-weight: 800; padding: 4px 12px; border-radius: 9999px; font-size: 0.75rem; border: 1px solid rgba(239,68,68,0.3); text-transform: uppercase;">
            SuperAdmin Mode
          </span>
        </div>
        <p style="color: #94a3b8; font-size: 0.975rem;">Global threat intelligence, user telemetry, revenue analytics, and system oversight.</p>
      </div>

      <div style="display: flex; gap: 10px;">
        <form method="POST" action="{{ route('admin.clear-cache') }}">
          @csrf
          <button type="submit" style="background: rgba(255,255,255,0.06); color: #cbd5e1; border: 1px solid rgba(255,255,255,0.12); padding: 0.65rem 1.25rem; border-radius: 10px; font-weight: 700; font-size: 0.85rem; cursor: pointer;">
            ⚡ Flush Cache
          </button>
        </form>
      </div>
    </div>

    <!-- Admin Nav Tabs -->
    <x-admin-nav />

    <!-- Metric KPI Cards -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.5rem; margin-bottom: 2.5rem;">

      <div style="background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(16px); border: 1px solid rgba(99, 102, 241, 0.2); border-radius: 18px; padding: 1.75rem;">
        <div style="color: #94a3b8; font-size: 0.85rem; font-weight: 600; margin-bottom: 4px;">Registered Users</div>
        <div style="font-size: 2.25rem; font-weight: 900; color: #fff;">{{ $totalUsers }}</div>
        <div style="font-size: 0.8rem; color: #818cf8; margin-top: 4px; font-weight: 600;">{{ $proSubscribers }} Pro Subscribers</div>
      </div>

      <div style="background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(16px); border: 1px solid rgba(16, 185, 129, 0.25); border-radius: 18px; padding: 1.75rem;">
        <div style="color: #94a3b8; font-size: 0.85rem; font-weight: 600; margin-bottom: 4px;">Total Platform Scans</div>
        <div style="font-size: 2.25rem; font-weight: 900; color: #10b981;">{{ $totalScans }}</div>
        <div style="font-size: 0.8rem; color: #10b981; margin-top: 4px; font-weight: 600;">Multi-Engine Active</div>
      </div>

      <div style="background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(16px); border: 1px solid rgba(239, 68, 68, 0.25); border-radius: 18px; padding: 1.75rem;">
        <div style="color: #94a3b8; font-size: 0.85rem; font-weight: 600; margin-bottom: 4px;">Threats Flagged</div>
        <div style="font-size: 2.25rem; font-weight: 900; color: #ef4444;">{{ $totalThreats }}</div>
        <div style="font-size: 0.8rem; color: #ef4444; margin-top: 4px; font-weight: 600;">High / Critical Risk</div>
      </div>

      <div style="background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(16px); border: 1px solid rgba(245, 158, 11, 0.25); border-radius: 18px; padding: 1.75rem;">
        <div style="color: #94a3b8; font-size: 0.85rem; font-weight: 600; margin-bottom: 4px;">Pending Reports</div>
        <div style="font-size: 2.25rem; font-weight: 900; color: #f59e0b;">{{ $pendingReports }}</div>
        <div style="font-size: 0.8rem; color: #f59e0b; margin-top: 4px; font-weight: 600;">Awaiting review</div>
      </div>

      <div style="background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(16px); border: 1px solid rgba(217, 70, 239, 0.25); border-radius: 18px; padding: 1.75rem;">
        <div style="color: #94a3b8; font-size: 0.85rem; font-weight: 600; margin-bottom: 4px;">Gross Revenue</div>
        <div style="font-size: 2.25rem; font-weight: 900; color: #f472b6;">${{ number_format($totalRevenue, 2) }}</div>
        <div style="font-size: 0.8rem; color: #f472b6; margin-top: 4px; font-weight: 600;">Razorpay Gateway</div>
      </div>

    </div>

    <!-- Two-Column Recent Activity Row -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(450px, 1fr)); gap: 2rem; margin-bottom: 2.5rem;">

      <!-- Recent Registered Users -->
      <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(99, 102, 241, 0.2); border-radius: 20px; padding: 1.75rem;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.25rem;">
          <h3 style="font-size: 1.15rem; font-weight: 800; color: #fff; margin: 0;">Recent Signups</h3>
          <a href="{{ route('admin.users') }}" style="color: #a5b4fc; font-size: 0.85rem; font-weight: 700; text-decoration: none;">View All Users →</a>
        </div>
        <div style="display: flex; flex-direction: column; gap: 10px;">
          @foreach($recentUsers as $u)
            <div style="background: #060814; border: 1px solid rgba(255,255,255,0.06); border-radius: 12px; padding: 0.85rem 1rem; display: flex; justify-content: space-between; align-items: center;">
              <div>
                <div style="font-weight: 700; color: #fff; font-size: 0.925rem;">{{ $u->username }}</div>
                <div style="color: #64748b; font-size: 0.8rem;">{{ $u->email }}</div>
              </div>
              <div style="text-align: right;">
                <span style="font-size: 0.75rem; font-weight: 800; text-transform: uppercase; padding: 2px 8px; border-radius: 4px; background: {{ $u->is_pro ? 'rgba(99,102,241,0.2)' : 'rgba(255,255,255,0.05)' }}; color: {{ $u->is_pro ? '#a5b4fc' : '#94a3b8' }};">
                  {{ $u->plan }}
                </span>
                <div style="color: #64748b; font-size: 0.75rem; margin-top: 3px;">{{ $u->created_at->diffForHumans() }}</div>
              </div>
            </div>
          @endforeach
        </div>
      </div>

      <!-- Recent User Threat Reports Pending -->
      <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(245, 158, 11, 0.25); border-radius: 20px; padding: 1.75rem;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.25rem;">
          <h3 style="font-size: 1.15rem; font-weight: 800; color: #fff; margin: 0;">Pending Threat Reports</h3>
          <a href="{{ route('admin.threats') }}" style="color: #f59e0b; font-size: 0.85rem; font-weight: 700; text-decoration: none;">Review Queue →</a>
        </div>
        @if($recentReports->isEmpty())
          <div style="text-align: center; padding: 2rem 1rem; color: #64748b; font-size: 0.9rem;">
            ✅ No pending user reports to review.
          </div>
        @else
          <div style="display: flex; flex-direction: column; gap: 10px;">
            @foreach($recentReports as $rep)
              <div style="background: #060814; border: 1px solid rgba(245,158,11,0.2); border-radius: 12px; padding: 0.85rem 1rem; display: flex; justify-content: space-between; align-items: center;">
                <div style="max-width: 70%;">
                  <div style="font-weight: 700; color: #fff; font-size: 0.9rem; word-break: break-all;">{{ Str::limit($rep->reported_url, 40) }}</div>
                  <div style="color: #94a3b8; font-size: 0.8rem;">{{ Str::limit($rep->description, 50) }}</div>
                </div>
                <div>
                  <a href="{{ route('admin.threats') }}" style="background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245,158,11,0.4); padding: 4px 10px; border-radius: 6px; font-size: 0.75rem; font-weight: 700; text-decoration: none;">
                    Review
                  </a>
                </div>
              </div>
            @endforeach
          </div>
        @endif
      </div>

    </div>

  </main>
</div>
@endsection
