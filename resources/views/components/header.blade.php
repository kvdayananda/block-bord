<header class="main-navbar" id="mainNavbar">
  <div class="nav-container">
    <a href="{{ route('landing') }}" class="nav-logo">
      <span class="logo-icon">🛡️</span>
      <span class="logo-text">Block Bord<span class="logo-accent">AI</span></span>
    </a>
    <nav class="nav-links">
      <a href="{{ route('landing') }}" class="nav-link">Home</a>
      <a href="{{ route('tools.home') }}" class="nav-link">Tools</a>
      <a href="{{ route('pricing') }}" class="nav-link">Pricing</a>
      <a href="{{ route('about') }}" class="nav-link">About</a>
      <a href="{{ route('contact') }}" class="nav-link">Contact</a>
    </nav>
    <div class="nav-actions">
      @auth
        <a href="{{ route('dashboard') }}" class="btn btn-secondary">Dashboard</a>
        <a href="{{ route('logout') }}" class="btn btn-primary">Logout</a>
      @else
        <a href="{{ route('login') }}" class="btn btn-secondary">Login</a>
        <a href="{{ route('register') }}" class="btn btn-primary">Get Started</a>
      @endauth
    </div>
  </div>
</header>
