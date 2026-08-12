@extends('layouts.app')
@section('title', 'Account Settings — Block Bord AI')
@section('content')
<div style="display: flex; min-height: calc(100vh - 70px);">
  <x-sidebar />
  <main style="flex: 1; padding: 2.5rem; background: #0f0f17; color: #fff;">
    <h1 style="font-size: 2rem; font-weight: 800; margin-bottom: 1.5rem;">Account Settings</h1>
    
    <div style="background: #1e1e2e; padding: 2rem; border-radius: 12px; max-width: 600px; border: 1px solid rgba(255,255,255,0.08); margin-bottom: 2rem;">
      <h3 style="font-size: 1.25rem; font-weight: 700; margin-bottom: 1rem;">Profile Information</h3>
      <p style="color: #94a3b8; margin-bottom: 0.5rem;"><strong>Username:</strong> {{ $user->username }}</p>
      <p style="color: #94a3b8; margin-bottom: 0.5rem;"><strong>Email:</strong> {{ $user->email }}</p>
      <p style="color: #94a3b8;"><strong>Plan:</strong> <span style="text-transform: uppercase; color: #818cf8; font-weight: 700;">{{ $user->plan }}</span></p>
    </div>

    <div style="background: #1e1e2e; padding: 2rem; border-radius: 12px; max-width: 600px; border: 1px solid rgba(255,255,255,0.08);">
      <h3 style="font-size: 1.25rem; font-weight: 700; margin-bottom: 1rem;">API Access Keys</h3>
      <p style="color: #94a3b8; margin-bottom: 1rem;">Use this API key to integrate Block Bord AI with your custom tools or Chrome extension.</p>
      <div style="background: #11111b; padding: 0.85rem; border-radius: 8px; font-family: monospace; color: #10b981; margin-bottom: 1rem; border: 1px solid #33334d;">
        {{ $user->api_key ?? 'No key generated' }}
      </div>
      <form action="{{ route('dashboard.api.generate_key') }}" method="POST">
        @csrf
        <button type="submit" style="background: #6366f1; color: #fff; padding: 0.75rem 1.25rem; border: none; border-radius: 8px; font-weight: 700; cursor: pointer;">Generate New Key</button>
      </form>
    </div>
  </main>
</div>
@endsection
