@extends('layouts.app')

@section('title', 'User Management — Admin Console — Block Bord AI')

@section('content')
<div style="display: flex; min-height: calc(100vh - 70px); background: #060814;">
  <x-sidebar />

  <main style="flex: 1; padding: 2.5rem; background: #060814; color: #fff;">

    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; flex-wrap: wrap; gap: 1rem;">
      <div>
        <h1 style="font-size: 2.25rem; font-weight: 900; color: #fff; margin: 0 0 4px 0;">User Account Management</h1>
        <p style="color: #94a3b8; font-size: 0.95rem; margin: 0;">Manage registered accounts, plan quotas, account status, and administrative roles.</p>
      </div>
    </div>

    <!-- Admin Nav Tabs -->
    <x-admin-nav />

    <!-- Filters & Search -->
    <div style="background: rgba(15, 23, 42, 0.75); border: 1px solid rgba(99, 102, 241, 0.2); border-radius: 16px; padding: 1.25rem 1.5rem; margin-bottom: 2rem;">
      <form method="GET" action="{{ route('admin.users') }}" style="display: flex; gap: 1rem; flex-wrap: wrap; align-items: center; justify-content: space-between;">

        <div style="flex: 1; min-width: 260px; position: relative;">
          <input type="text" name="search" value="{{ $currentSearch ?? '' }}" placeholder="Search by username or email address..." style="width: 100%; background: #060814; border: 1px solid rgba(255,255,255,0.12); color: #fff; padding: 0.65rem 1rem 0.65rem 2.5rem; border-radius: 10px; font-size: 0.9rem; outline: none;">
          <span style="position: absolute; left: 0.85rem; top: 50%; transform: translateY(-50%); color: #64748b;">🔍</span>
        </div>

        <div style="display: flex; gap: 10px; flex-wrap: wrap; align-items: center;">
          <select name="plan" onchange="this.form.submit()" style="background: #060814; color: #cbd5e1; border: 1px solid rgba(255,255,255,0.12); padding: 0.65rem 1rem; border-radius: 10px; font-size: 0.85rem; outline: none;">
            <option value="all" {{ ($currentPlan ?? 'all') === 'all' ? 'selected' : '' }}>All Plans</option>
            <option value="free" {{ ($currentPlan ?? '') === 'free' ? 'selected' : '' }}>Free</option>
            <option value="pro" {{ ($currentPlan ?? '') === 'pro' ? 'selected' : '' }}>Pro</option>
            <option value="business" {{ ($currentPlan ?? '') === 'business' ? 'selected' : '' }}>Business</option>
          </select>

          <select name="status" onchange="this.form.submit()" style="background: #060814; color: #cbd5e1; border: 1px solid rgba(255,255,255,0.12); padding: 0.65rem 1rem; border-radius: 10px; font-size: 0.85rem; outline: none;">
            <option value="all" {{ ($currentStatus ?? 'all') === 'all' ? 'selected' : '' }}>All Status</option>
            <option value="active" {{ ($currentStatus ?? '') === 'active' ? 'selected' : '' }}>Active</option>
            <option value="suspended" {{ ($currentStatus ?? '') === 'suspended' ? 'selected' : '' }}>Suspended</option>
          </select>

          @if($currentSearch || $currentPlan !== 'all' || $currentStatus !== 'all')
            <a href="{{ route('admin.users') }}" style="color: #f87171; font-size: 0.85rem; font-weight: 600; text-decoration: none;">✕ Reset</a>
          @endif
        </div>

      </form>
    </div>

    <!-- Users Table -->
    <div style="background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(20px); border-radius: 20px; border: 1px solid rgba(99, 102, 241, 0.2); padding: 1.5rem; box-shadow: 0 12px 32px rgba(0,0,0,0.5);">
      <div style="overflow-x: auto;">
        <table style="width: 100%; border-collapse: collapse; text-align: left; color: #cbd5e1;">
          <thead>
            <tr style="border-bottom: 1px solid rgba(99, 102, 241, 0.2); color: #94a3b8; font-size: 0.825rem; text-transform: uppercase; letter-spacing: 0.05em;">
              <th style="padding: 1rem;">ID</th>
              <th style="padding: 1rem;">User Profile</th>
              <th style="padding: 1rem;">Tier Plan</th>
              <th style="padding: 1rem;">Account Status</th>
              <th style="padding: 1rem;">Role</th>
              <th style="padding: 1rem;">Joined</th>
              <th style="padding: 1rem; text-align: right;">Actions</th>
            </tr>
          </thead>
          <tbody>
            @foreach($users as $user)
              <tr style="border-bottom: 1px solid rgba(255,255,255,0.05); transition: background 0.2s;" onmouseover="this.style.background='rgba(99,102,241,0.08)'" onmouseout="this.style.background='transparent'">
                <td style="padding: 1rem; font-family: var(--font-mono, monospace); color: #64748b;">#{{ $user->id }}</td>
                <td style="padding: 1rem;">
                  <div style="font-weight: 800; color: #fff; font-size: 0.95rem;">{{ $user->username }}</div>
                  <div style="color: #94a3b8; font-size: 0.8rem;">{{ $user->email }}</div>
                </td>
                <td style="padding: 1rem;">
                  <form method="POST" action="{{ route('admin.users.update-plan', $user->id) }}" style="display: inline;">
                    @csrf
                    <select name="plan" onchange="this.form.submit()" style="background: #060814; color: {{ $user->plan === 'pro' ? '#a5b4fc' : ($user->plan === 'business' ? '#f472b6' : '#94a3b8') }}; border: 1px solid rgba(255,255,255,0.1); padding: 4px 8px; border-radius: 6px; font-size: 0.775rem; font-weight: 700; text-transform: uppercase; outline: none;">
                      <option value="free" {{ $user->plan === 'free' ? 'selected' : '' }}>Free</option>
                      <option value="pro" {{ $user->plan === 'pro' ? 'selected' : '' }}>Pro</option>
                      <option value="business" {{ $user->plan === 'business' ? 'selected' : '' }}>Business</option>
                    </select>
                  </form>
                </td>
                <td style="padding: 1rem;">
                  <span style="padding: 0.3rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 800; text-transform: uppercase; background: {{ $user->is_active ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)' }}; color: {{ $user->is_active ? '#10b981' : '#ef4444' }}; border: 1px solid {{ $user->is_active ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)' }};">
                    {{ $user->is_active ? 'Active' : 'Suspended' }}
                  </span>
                </td>
                <td style="padding: 1rem;">
                  @if($user->is_admin)
                    <span style="background: rgba(239, 68, 68, 0.15); color: #ef4444; border: 1px solid rgba(239,68,68,0.3); padding: 3px 8px; border-radius: 6px; font-size: 0.75rem; font-weight: 800;">ADMIN</span>
                  @else
                    <span style="color: #64748b; font-size: 0.8rem;">Member</span>
                  @endif
                </td>
                <td style="padding: 1rem; color: #64748b; font-size: 0.825rem;">
                  {{ $user->created_at->format('M d, Y') }}
                </td>
                <td style="padding: 1rem; text-align: right;">
                  <div style="display: inline-flex; gap: 6px;">
                    <!-- Toggle Status -->
                    <form method="POST" action="{{ route('admin.users.toggle-status', $user->id) }}">
                      @csrf
                      <button type="submit" style="background: {{ $user->is_active ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)' }}; color: {{ $user->is_active ? '#f87171' : '#34d399' }}; border: 1px solid {{ $user->is_active ? 'rgba(239, 68, 68, 0.3)' : 'rgba(16, 185, 129, 0.3)' }}; padding: 4px 10px; border-radius: 6px; font-size: 0.75rem; font-weight: 700; cursor: pointer;">
                        {{ $user->is_active ? 'Suspend' : 'Activate' }}
                      </button>
                    </form>

                    <!-- Toggle Admin Role -->
                    <form method="POST" action="{{ route('admin.users.toggle-admin', $user->id) }}">
                      @csrf
                      <button type="submit" style="background: rgba(255,255,255,0.06); color: #cbd5e1; border: 1px solid rgba(255,255,255,0.1); padding: 4px 10px; border-radius: 6px; font-size: 0.75rem; font-weight: 700; cursor: pointer;">
                        {{ $user->is_admin ? 'Demote' : 'Promote Admin' }}
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
        {{ $users->links() }}
      </div>
    </div>

  </main>
</div>
@endsection
