@extends('layouts.app')
@section('title', 'Custom Domain Controls — Block Bord AI')
@section('content')
<div style="display: flex; min-height: calc(100vh - 70px);">
  <x-sidebar />
  <main style="flex: 1; padding: 2.5rem; background: #0f0f17; color: #fff;">
    <h1 style="font-size: 2rem; font-weight: 800; margin-bottom: 1.5rem;">Custom Block & Allow Lists</h1>
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 2rem;">
      <div style="background: #1e1e2e; padding: 1.5rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08);">
        <h3 style="color: #ef4444; font-size: 1.25rem; font-weight: 700; margin-bottom: 1rem;">⛔ Custom Blacklist</h3>
        @if($blacklists->isEmpty())
          <p style="color: #94a3b8;">No blacklisted domains added.</p>
        @else
          <ul style="color: #cbd5e1;">
            @foreach($blacklists as $item)
              <li>{{ $item->domain }}</li>
            @endforeach
          </ul>
        @endif
      </div>
      <div style="background: #1e1e2e; padding: 1.5rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08);">
        <h3 style="color: #10b981; font-size: 1.25rem; font-weight: 700; margin-bottom: 1rem;">✅ Custom Whitelist</h3>
        @if($whitelists->isEmpty())
          <p style="color: #94a3b8;">No whitelisted domains added.</p>
        @else
          <ul style="color: #cbd5e1;">
            @foreach($whitelists as $item)
              <li>{{ $item->domain }}</li>
            @endforeach
          </ul>
        @endif
      </div>
    </div>
  </main>
</div>
@endsection
