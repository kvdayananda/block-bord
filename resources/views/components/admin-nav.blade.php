<div style="background: rgba(15, 23, 42, 0.9); border: 1px solid rgba(99, 102, 241, 0.25); border-radius: 16px; padding: 0.75rem 1rem; margin-bottom: 2rem; display: flex; gap: 8px; flex-wrap: wrap; align-items: center;">
  <a href="{{ route('admin.dashboard') }}" style="padding: 0.5rem 0.9rem; border-radius: 8px; font-size: 0.85rem; font-weight: 700; text-decoration: none; transition: all 0.2s; background: {{ request()->routeIs('admin.dashboard') ? 'rgba(99, 102, 241, 0.3)' : 'transparent' }}; color: {{ request()->routeIs('admin.dashboard') ? '#fff' : '#94a3b8' }};">
    ⚡ Overview
  </a>
  <a href="{{ route('admin.users') }}" style="padding: 0.5rem 0.9rem; border-radius: 8px; font-size: 0.85rem; font-weight: 700; text-decoration: none; transition: all 0.2s; background: {{ request()->routeIs('admin.users*') ? 'rgba(99, 102, 241, 0.3)' : 'transparent' }}; color: {{ request()->routeIs('admin.users*') ? '#fff' : '#94a3b8' }};">
    👥 Users
  </a>
  <a href="{{ route('admin.scans') }}" style="padding: 0.5rem 0.9rem; border-radius: 8px; font-size: 0.85rem; font-weight: 700; text-decoration: none; transition: all 0.2s; background: {{ request()->routeIs('admin.scans*') ? 'rgba(99, 102, 241, 0.3)' : 'transparent' }}; color: {{ request()->routeIs('admin.scans*') ? '#fff' : '#94a3b8' }};">
    🔍 All Scans
  </a>
  <a href="{{ route('admin.threats') }}" style="padding: 0.5rem 0.9rem; border-radius: 8px; font-size: 0.85rem; font-weight: 700; text-decoration: none; transition: all 0.2s; background: {{ request()->routeIs('admin.threats*') ? 'rgba(99, 102, 241, 0.3)' : 'transparent' }}; color: {{ request()->routeIs('admin.threats*') ? '#fff' : '#94a3b8' }};">
    🛡️ Threat Reports
  </a>
  <a href="{{ route('admin.blacklist') }}" style="padding: 0.5rem 0.9rem; border-radius: 8px; font-size: 0.85rem; font-weight: 700; text-decoration: none; transition: all 0.2s; background: {{ request()->routeIs('admin.blacklist*') ? 'rgba(99, 102, 241, 0.3)' : 'transparent' }}; color: {{ request()->routeIs('admin.blacklist*') ? '#fff' : '#94a3b8' }};">
    🚫 Blacklist
  </a>
  <a href="{{ route('admin.whitelist') }}" style="padding: 0.5rem 0.9rem; border-radius: 8px; font-size: 0.85rem; font-weight: 700; text-decoration: none; transition: all 0.2s; background: {{ request()->routeIs('admin.whitelist*') ? 'rgba(99, 102, 241, 0.3)' : 'transparent' }}; color: {{ request()->routeIs('admin.whitelist*') ? '#fff' : '#94a3b8' }};">
    ✅ Whitelist
  </a>
  <a href="{{ route('admin.payments') }}" style="padding: 0.5rem 0.9rem; border-radius: 8px; font-size: 0.85rem; font-weight: 700; text-decoration: none; transition: all 0.2s; background: {{ request()->routeIs('admin.payments*') ? 'rgba(99, 102, 241, 0.3)' : 'transparent' }}; color: {{ request()->routeIs('admin.payments*') ? '#fff' : '#94a3b8' }};">
    💳 Payments
  </a>
  <a href="{{ route('admin.api-usage') }}" style="padding: 0.5rem 0.9rem; border-radius: 8px; font-size: 0.85rem; font-weight: 700; text-decoration: none; transition: all 0.2s; background: {{ request()->routeIs('admin.api-usage*') ? 'rgba(99, 102, 241, 0.3)' : 'transparent' }}; color: {{ request()->routeIs('admin.api-usage*') ? '#fff' : '#94a3b8' }};">
    📊 API Telemetry
  </a>
  <a href="{{ route('admin.logs') }}" style="padding: 0.5rem 0.9rem; border-radius: 8px; font-size: 0.85rem; font-weight: 700; text-decoration: none; transition: all 0.2s; background: {{ request()->routeIs('admin.logs*') ? 'rgba(99, 102, 241, 0.3)' : 'transparent' }}; color: {{ request()->routeIs('admin.logs*') ? '#fff' : '#94a3b8' }};">
    ⚙️ System Logs
  </a>
</div>
