<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="theme-color" content="#6366f1">
  <link rel="stylesheet" href="/static/style.css?v=8.0">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Plus+Jakarta+Sans:wght@700;800;900&display=swap" rel="stylesheet">
  <link rel="icon" href="/static/favicon.ico">
  <meta name="csrf-token" content="{{ csrf_token() }}">
  <meta name="description" content="@yield('meta_description', 'Block Bord AI is an AI-powered cybersecurity platform that protects users from phishing attacks, malware, dark-web leaks, and online threats with real-time analysis and intelligent detection.')">
  <meta name="keywords" content="AI Cybersecurity Platform, Phishing Detection, URL Scanner, Website Security Checker, Domain Reputation Checker, IP Reputation Checker, Email Phishing Detector, QR Code Security Scanner, UPI Fraud Detection, Scam Detection, Malware Detection, Browser Security, Threat Intelligence, Cyber Threat Protection, Online Fraud Prevention, AI Security Assistant, Safe Browsing, Cybersecurity Tools">
  <title>@yield('title', 'Block Bord AI')</title>

  <meta property="og:title" content="@yield('title', 'Block Bord AI')">
  <meta property="og:description" content="@yield('og_description', 'Block Bord AI — Enterprise-grade AI cybersecurity. URL Scanner, Phishing Detector, IP Reputation, Email Leak Checker, UPI Fraud Detection, and more.')">
  <meta property="og:type" content="website">
  <meta property="og:url" content="{{ url()->current() }}">
  <meta property="og:image" content="/static/og-image.png">
  <meta property="og:site_name" content="Block Bord AI">
  <meta property="og:locale" content="en_US">

  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:site" content="@BlockBordAI">
  <meta name="twitter:title" content="@yield('title', 'Block Bord AI')">
  <meta name="twitter:description" content="@yield('twitter_description', 'Block Bord AI — Enterprise-grade AI cybersecurity. URL Scanner, Phishing Detector, IP Reputation, Email Leak Checker, UPI Fraud Detection, and more.')">
  <meta name="twitter:image" content="/static/og-image.png">
  <link rel="canonical" href="{{ url()->current() }}">

  <script type="application/ld+json">
  {
    "@@context": "https://schema.org",
    "@type": "WebSite",
    "name": "Block Bord AI",
    "url": "https://blockbord.ai",
    "description": "AI-powered cybersecurity platform providing URL scanning, phishing detection, IP reputation analysis, email leak checking, and threat intelligence."
  }
  </script>
  @yield('extra_head')
</head>
<body style="min-height: 100vh; display: flex; flex-direction: column; background: #060814; color: #f8fafc; margin: 0;">

  @if(session('success'))
    <div style="position: fixed; top: 1rem; right: 1rem; z-index: 9999; background: #10B981; color: white; padding: 0.75rem 1.5rem; border-radius: 8px; font-weight: 600; box-shadow: 0 10px 25px rgba(0,0,0,0.2);">
      {{ session('success') }}
    </div>
  @endif

  @if(session('error'))
    <div style="position: fixed; top: 1rem; right: 1rem; z-index: 9999; background: #EF4444; color: white; padding: 0.75rem 1.5rem; border-radius: 8px; font-weight: 600; box-shadow: 0 10px 25px rgba(0,0,0,0.2);">
      {{ session('error') }}
    </div>
  @endif

  <x-header />

  <main style="flex: 1;">
    @yield('content')
  </main>

  <x-footer />

  @yield('extra_scripts')
</body>
</html>
