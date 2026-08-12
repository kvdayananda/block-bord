<footer class="main-footer">
  <div class="footer-container">
    <div class="footer-brand">
      <div class="footer-logo">
        <span class="logo-icon">🛡️</span>
        <span class="logo-text">Block Bord<span class="logo-accent">AI</span></span>
      </div>
      <p class="footer-tagline">Cyber Intelligence for the Next Billion. Real-time AI shield and phishing defense.</p>
    </div>
    <div class="footer-links">
      <div class="footer-column">
        <h4>Product</h4>
        <a href="{{ route('tools.home') }}">Security Tools</a>
        <a href="{{ route('pricing') }}">Pricing Plans</a>
        <a href="{{ route('extension.setup') }}">Chrome Extension</a>
      </div>
      <div class="footer-column">
        <h4>Company</h4>
        <a href="{{ route('about') }}">About Us</a>
        <a href="{{ route('contact') }}">Contact</a>
        <a href="{{ route('status') }}">System Status</a>
      </div>
      <div class="footer-column">
        <h4>Legal</h4>
        <a href="{{ route('privacy') }}">Privacy Policy</a>
        <a href="{{ route('terms') }}">Terms of Service</a>
        <a href="{{ route('cookie') }}">Cookie Policy</a>
      </div>
    </div>
  </div>
  <div class="footer-bottom">
    <p>&copy; {{ date('Y') }} Block Bord AI. All rights reserved.</p>
  </div>
</footer>
