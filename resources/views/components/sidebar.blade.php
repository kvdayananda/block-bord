<aside class="sidebar" id="dashboardSidebar">
  <div class="sidebar-brand" style="position: relative;">
    <div style="display: flex; align-items: center;">
      <span class="brand-icon">🛡️</span>
      <span class="brand-name">Block Bord AI</span>
    </div>
    <button id="sidebarToggleBtn" class="sidebar-toggle-btn" aria-label="Toggle Sidebar">
      ◀
    </button>
  </div>
  <nav class="sidebar-nav">
    <a href="{{ route('dashboard') }}" class="nav-item {{ request()->routeIs('dashboard') ? 'active' : '' }}">
      <span class="icon">📊</span> <span class="nav-label">Overview</span>
    </a>
    <a href="{{ route('history') }}" class="nav-item {{ request()->routeIs('history') ? 'active' : '' }}">
      <span class="icon">📜</span> <span class="nav-label">Scan History</span>
    </a>
    <a href="{{ route('reports.index') }}" class="nav-item {{ request()->routeIs('reports.*') ? 'active' : '' }}">
      <span class="icon">📑</span> <span class="nav-label">Reports</span>
    </a>
    <a href="{{ route('security.score') }}" class="nav-item {{ request()->routeIs('security.score') ? 'active' : '' }}">
      <span class="icon">⚡</span> <span class="nav-label">Security Score</span>
    </a>
    <a href="{{ route('tools.home') }}" class="nav-item {{ request()->routeIs('tools.*') ? 'active' : '' }}">
      <span class="icon">🧰</span> <span class="nav-label">Security Suite</span>
    </a>
    <a href="{{ route('ai.page') }}" class="nav-item {{ request()->routeIs('ai.*') ? 'active' : '' }}">
      <span class="icon">🤖</span> <span class="nav-label">AI Copilot</span>
    </a>
    <a href="{{ route('notifications.index') }}" class="nav-item {{ request()->routeIs('notifications.*') ? 'active' : '' }}">
      <span class="icon">🔔</span> <span class="nav-label">Notifications</span>
      @php
        $sidebarUnread = auth()->check() ? \App\Models\Notification::where('user_id', auth()->id())->where('is_read', false)->count() : 0;
      @endphp
      @if($sidebarUnread > 0)
        <span class="nav-badge" style="margin-left: auto; background: #ef4444; color: #fff; font-size: 0.7rem; font-weight: 800; padding: 2px 7px; border-radius: 9999px;">
          {{ $sidebarUnread }}
        </span>
      @endif
    </a>
    <a href="{{ route('subscription') }}" class="nav-item {{ request()->routeIs('subscription') ? 'active' : '' }}">
      <span class="icon">💳</span> <span class="nav-label">Subscription</span>
    </a>
    <a href="{{ route('analytics') }}" class="nav-item {{ request()->routeIs('analytics') ? 'active' : '' }}">
      <span class="icon">📈</span> <span class="nav-label">Analytics</span>
    </a>
    <a href="{{ route('settings') }}" class="nav-item {{ request()->routeIs('settings') ? 'active' : '' }}">
      <span class="icon">⚙️</span> <span class="nav-label">Settings</span>
    </a>
    @if(auth()->user() && auth()->user()->is_admin)
      <a href="{{ route('admin.dashboard') }}" class="nav-item {{ request()->routeIs('admin.*') ? 'active' : '' }}">
        <span class="icon">👑</span> <span class="nav-label">Admin Console</span>
      </a>
    @endif
  </nav>
</aside>

<script>
  document.addEventListener('DOMContentLoaded', () => {
    const sidebar = document.getElementById('dashboardSidebar');
    const toggleBtn = document.getElementById('sidebarToggleBtn');

    // Auto collapse on tablet
    if(window.innerWidth > 768 && window.innerWidth <= 1024) {
        sidebar.classList.add('collapsed');
    }

    if(toggleBtn && sidebar) {
      toggleBtn.addEventListener('click', () => {
        sidebar.classList.toggle('collapsed');
      });
    }
  });
</script>
