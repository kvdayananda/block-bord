@extends('layouts.app')
@section('title', 'Admin Dashboard — Block Bord AI')
@section('content')
<div style="display: flex; min-height: calc(100vh - 70px);">
  <x-sidebar />
  <main style="flex: 1; padding: 2.5rem; background: #0f0f17; color: #fff;">
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 2rem;">
      <h1 style="font-size: 2rem; font-weight: 800;">⚡ Admin Intelligence Dashboard</h1>
      <span style="background: #ef4444; color: #fff; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.8rem; font-weight: 700;">SYSTEM ADMIN MODE</span>
    </div>

    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.5rem; margin-bottom: 2.5rem;">
      <div style="background: #1e1e2e; padding: 1.5rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08);">
        <div style="color: #94a3b8;">Total Users</div>
        <div style="font-size: 2rem; font-weight: 800; color: #6366f1;">{{ $totalUsers }}</div>
      </div>
      <div style="background: #1e1e2e; padding: 1.5rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08);">
        <div style="color: #94a3b8;">Total System Scans</div>
        <div style="font-size: 2rem; font-weight: 800; color: #10b981;">{{ $totalScans }}</div>
      </div>
      <div style="background: #1e1e2e; padding: 1.5rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08);">
        <div style="color: #94a3b8;">Threats Flagged</div>
        <div style="font-size: 2rem; font-weight: 800; color: #ef4444;">{{ $totalThreats }}</div>
      </div>
      <div style="background: #1e1e2e; padding: 1.5rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08);">
        <div style="color: #94a3b8;">Pending User Reports</div>
        <div style="font-size: 2rem; font-weight: 800; color: #f59e0b;">{{ $pendingReports }}</div>
      </div>
    </div>

    <div style="display: flex; gap: 1rem;">
      <a href="{{ route('admin.users') }}" style="background: #33334d; color: #fff; padding: 0.75rem 1.25rem; border-radius: 8px; font-weight: 600; text-decoration: none;">Manage Users</a>
      <a href="{{ route('admin.blacklist') }}" style="background: #33334d; color: #fff; padding: 0.75rem 1.25rem; border-radius: 8px; font-weight: 600; text-decoration: none;">Global Blacklist</a>
      <a href="{{ route('admin.whitelist') }}" style="background: #33334d; color: #fff; padding: 0.75rem 1.25rem; border-radius: 8px; font-weight: 600; text-decoration: none;">Global Whitelist</a>
    </div>
  </main>
</div>
@endsection
