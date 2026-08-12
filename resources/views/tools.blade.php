@extends('layouts.app')

@section('title', 'Security Tools Suite — Block Bord AI')

@section('content')
<section style="padding: 3rem 1.5rem; max-width: 1200px; margin: 0 auto; color: #fff;">
  <h1 style="font-size: 2.5rem; font-weight: 800; margin-bottom: 0.5rem; text-align: center;">Security Tools Suite</h1>
  <p style="color: #94a3b8; text-align: center; margin-bottom: 3rem;">All-in-one AI & Heuristic Security Analysis</p>

  <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 2rem;">
    <!-- URL Scan Tool -->
    <div style="background: #1e1e2e; padding: 2rem; border-radius: 14px; border: 1px solid rgba(255,255,255,0.08);">
      <h3 style="font-size: 1.25rem; font-weight: 700; margin-bottom: 1rem;">🔗 URL Phishing Scanner</h3>
      <form action="{{ route('scan') }}" method="POST">
        @csrf
        <input type="text" name="url" placeholder="https://suspicious-site.com" required style="width: 100%; padding: 0.75rem; border-radius: 8px; border: 1px solid #33334d; background: #11111b; color: #fff; margin-bottom: 1rem;">
        <button type="submit" style="width: 100%; padding: 0.75rem; background: #6366f1; color: #fff; border: none; border-radius: 8px; font-weight: 700; cursor: pointer;">Scan URL</button>
      </form>
    </div>

    <!-- Domain Lookup Tool -->
    <div style="background: #1e1e2e; padding: 2rem; border-radius: 14px; border: 1px solid rgba(255,255,255,0.08);">
      <h3 style="font-size: 1.25rem; font-weight: 700; margin-bottom: 1rem;">🌐 Domain Intelligence</h3>
      <form action="{{ route('tools.lookup-domain') }}" method="POST">
        @csrf
        <input type="text" name="domain" placeholder="example.com" required style="width: 100%; padding: 0.75rem; border-radius: 8px; border: 1px solid #33334d; background: #11111b; color: #fff; margin-bottom: 1rem;">
        <button type="submit" style="width: 100%; padding: 0.75rem; background: #4f46e5; color: #fff; border: none; border-radius: 8px; font-weight: 700; cursor: pointer;">Lookup Domain</button>
      </form>
    </div>

    <!-- IP Lookup Tool -->
    <div style="background: #1e1e2e; padding: 2rem; border-radius: 14px; border: 1px solid rgba(255,255,255,0.08);">
      <h3 style="font-size: 1.25rem; font-weight: 700; margin-bottom: 1rem;">📍 IP Reputation Checker</h3>
      <form action="{{ route('tools.lookup-ip') }}" method="POST">
        @csrf
        <input type="text" name="ip" placeholder="8.8.8.8" required style="width: 100%; padding: 0.75rem; border-radius: 8px; border: 1px solid #33334d; background: #11111b; color: #fff; margin-bottom: 1rem;">
        <button type="submit" style="width: 100%; padding: 0.75rem; background: #4f46e5; color: #fff; border: none; border-radius: 8px; font-weight: 700; cursor: pointer;">Check IP</button>
      </form>
    </div>
  </div>
</section>
@endsection
