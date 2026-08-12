@extends('layouts.app')

@section('title', 'Login - Block Bord AI')

@section('content')
<div class="auth-wrapper">
  <div class="auth-brand-panel">
    <div style="position:relative; z-index:1;">
      <div style="display:flex; align-items:center; gap:10px; margin-bottom:40px;">
        <svg width="32" height="32" viewBox="0 0 24 24" fill="white">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        <span style="font-family:var(--font-display); font-size:1.3rem; font-weight:800; color:#fff;">Block Bord AI</span>
      </div>

      <h2 class="auth-brand-title">Enterprise-grade<br>security intelligence.</h2>
      <p class="auth-brand-sub">Scan threats, detect leaks, and protect your digital assets — all in one platform trusted by 50,000+ security professionals.</p>

      <div class="auth-feature-list">
        <div class="auth-feature-item">
          <div class="auth-feature-icon">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
          </div>
          Real-time URL & domain scanning
        </div>
        <div class="auth-feature-item">
          <div class="auth-feature-icon">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
          </div>
          Email leak detection
        </div>
        <div class="auth-feature-item">
          <div class="auth-feature-icon">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
          </div>
          Browser extension protection
        </div>
        <div class="auth-feature-item">
          <div class="auth-feature-icon">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5"><polyline points="20 6 9 17 4 12"/></svg>
          </div>
          Global threat intelligence map
        </div>
      </div>
    </div>
  </div>

  <div class="auth-form-panel">
    <div class="auth-card">
      <h2>Welcome back</h2>
      <p class="auth-subtitle">Sign in to your security dashboard</p>

      @if(session('error'))
      <div class="error-box" style="margin-bottom:20px;">{{ session('error') }}</div>
      @endif

      @if(session('success'))
      <div class="success-box" style="margin-bottom:20px;">{{ session('success') }}</div>
      @endif

      <form method="POST" action="{{ route('login') }}" class="auth-form">
        @csrf

        <div class="input-group">
          <label for="email">Username or Email</label>
          <input type="text" id="email" name="email" value="{{ old('email') }}" placeholder="your_username or email@example.com" required autocomplete="username">
        </div>

        <div class="input-group">
          <label for="password">Password</label>
          <div style="position:relative;">
            <input type="password" id="password" name="password" placeholder="••••••••" required autocomplete="current-password" style="padding-right:44px;">
            <button type="button" onclick="togglePass('password')" style="position:absolute; right:14px; top:50%; transform:translateY(-50%); color:var(--text-dim); background:none; border:none; cursor:pointer; display:flex; align-items:center;" aria-label="Show password">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
            </button>
          </div>
        </div>

        <div style="display:flex; justify-content:space-between; align-items:center; margin-top:-8px;">
          <label style="font-size:0.8125rem; color:var(--text-dim); cursor:pointer;">
            <input type="checkbox" name="remember" value="1"> Remember me
          </label>
          <a href="{{ route('password.request') }}" style="font-size:0.8125rem; color:var(--primary); font-weight:500;">Forgot password?</a>
        </div>

        <button type="submit" class="btn btn-primary btn-full" style="margin-top:4px;">
          Sign In
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 18 15 12 9 6"/></svg>
        </button>
      </form>

      <div class="auth-footer">
        Don't have an account? <a href="{{ route('register') }}">Create one free</a>
      </div>
    </div>
  </div>
</div>

<script>
function togglePass(id) {
  const inp = document.getElementById(id);
  inp.type = inp.type === 'password' ? 'text' : 'password';
}
</script>
@endsection
