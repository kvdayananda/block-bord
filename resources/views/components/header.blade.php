<header class="main-navbar" id="mainNavbar">
  <div class="nav-container" style="position: relative;">
    <a href="{{ route('landing') }}" class="nav-logo">
      <span class="logo-icon">🛡️</span>
      <span class="logo-text">Block Bord<span class="logo-accent">AI</span></span>
    </a>

    <!-- Hamburger Icon -->
    <button class="hamburger-menu" id="mobileMenuBtn" aria-label="Toggle navigation">
      <span></span>
      <span></span>
      <span></span>
    </button>

    <!-- Nav Wrapper (handles dropdown on mobile) -->
    <div class="nav-wrapper" id="navWrapper">
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
  </div>
</header>

<script>
  document.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('mobileMenuBtn');
    const wrapper = document.getElementById('navWrapper');
    if(btn && wrapper) {
      btn.addEventListener('click', () => {
        btn.classList.toggle('active');
        wrapper.classList.toggle('active');
      });
    }
  });
</script>
