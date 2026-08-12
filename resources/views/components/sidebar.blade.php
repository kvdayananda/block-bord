<aside class="sidebar">
  <div class="sidebar-brand">
    <span class="brand-icon">🛡️</span>
    <span class="brand-name">Block Bord AI</span>
  </div>
  <nav class="sidebar-nav">
    <a href="{{ route('dashboard') }}" class="nav-item {{ request()->routeIs('dashboard') ? 'active' : '' }}">
      <span class="icon">📊</span> Overview
    </a>
    <a href="{{ route('history') }}" class="nav-item {{ request()->routeIs('history') ? 'active' : '' }}">
      <span class="icon">📜</span> Scan History
    </a>
    <a href="{{ route('tools.home') }}" class="nav-item {{ request()->routeIs('tools.*') ? 'active' : '' }}">
      <span class="icon">🧰</span> Security Suite
    </a>
    <a href="{{ route('ai.page') }}" class="nav-item {{ request()->routeIs('ai.*') ? 'active' : '' }}">
      <span class="icon">🤖</span> AI Copilot
    </a>
    <a href="{{ route('analytics') }}" class="nav-item {{ request()->routeIs('analytics') ? 'active' : '' }}">
      <span class="icon">📈</span> Analytics
    </a>
    <a href="{{ route('settings') }}" class="nav-item {{ request()->routeIs('settings') ? 'active' : '' }}">
      <span class="icon">⚙️</span> Settings
    </a>
    @if(auth()->user() && auth()->user()->is_admin)
      <a href="{{ route('admin.dashboard') }}" class="nav-item {{ request()->routeIs('admin.*') ? 'active' : '' }}">
        <span class="icon">👑</span> Admin Console
      </a>
    @endif
  </nav>
</aside>
