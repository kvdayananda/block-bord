@extends('layouts.app')

@section('title', 'Account & API Key Settings — Block Bord AI')

@section('content')
<div style="display: flex; min-height: calc(100vh - 70px); background: #060814;">
  <x-sidebar />

  <main style="flex: 1; padding: 2.5rem; background: #060814; color: #fff;">
    
    <div style="margin-bottom: 2.5rem;">
      <h1 style="font-size: 2.25rem; font-weight: 900; color: #fff; margin-bottom: 0.5rem;">Account & Security Settings</h1>
      <p style="color: #94a3b8; font-size: 1rem;">Manage your user profile details, plan entitlements, and API keys.</p>
    </div>

    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(360px, 1fr)); gap: 2rem;">
      
      <!-- Profile Info Card -->
      <div style="background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(20px); border-radius: 20px; border: 1px solid rgba(99, 102, 241, 0.2); padding: 2.25rem; box-shadow: 0 12px 32px rgba(0,0,0,0.5);">
        <h3 style="font-size: 1.35rem; font-weight: 800; margin-bottom: 1.5rem; display: flex; align-items: center; gap: 10px;">
          <span>👤</span> User Profile Information
        </h3>

        <div style="display: flex; flex-direction: column; gap: 1.25rem;">
          <div>
            <label style="color: #64748b; font-size: 0.85rem; font-weight: 700; text-transform: uppercase;">Username</label>
            <div style="font-size: 1.1rem; font-weight: 700; color: #fff; margin-top: 4px;">{{ $user->username }}</div>
          </div>

          <div>
            <label style="color: #64748b; font-size: 0.85rem; font-weight: 700; text-transform: uppercase;">Registered Email</label>
            <div style="font-size: 1.1rem; font-weight: 700; color: #fff; margin-top: 4px;">{{ $user->email }}</div>
          </div>

          <div>
            <label style="color: #64748b; font-size: 0.85rem; font-weight: 700; text-transform: uppercase;">Current Subscription Plan</label>
            <div style="margin-top: 4px;">
              <span style="background: rgba(99, 102, 241, 0.25); color: #a5b4fc; font-weight: 800; padding: 4px 12px; border-radius: 9999px; font-size: 0.85rem; text-transform: uppercase; border: 1px solid rgba(99,102,241,0.4);">
                {{ $user->plan }} Tier
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- API Key Management Card -->
      <div style="background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(20px); border-radius: 20px; border: 1px solid rgba(99, 102, 241, 0.2); padding: 2.25rem; box-shadow: 0 12px 32px rgba(0,0,0,0.5);">
        <h3 style="font-size: 1.35rem; font-weight: 800; margin-bottom: 1rem; display: flex; align-items: center; gap: 10px;">
          <span>🔑</span> API Access Credentials
        </h3>
        <p style="color: #94a3b8; font-size: 0.925rem; margin-bottom: 1.5rem; line-height: 1.5;">
          Use your private API key to integrate Block Bord AI with your custom tools or Chrome Extension background worker.
        </p>

        <div style="background: #060814; border: 1.5px solid rgba(99, 102, 241, 0.3); padding: 1.1rem 1.25rem; border-radius: 12px; font-family: var(--font-mono, monospace); color: #10b981; font-weight: 700; font-size: 0.95rem; margin-bottom: 1.5rem; word-break: break-all; display: flex; justify-content: space-between; align-items: center;">
          <span id="apiKeyText">{{ $user->api_key ?? 'No Active API Key' }}</span>
          @if($user->api_key)
            <button type="button" onclick="navigator.clipboard.writeText('{{ $user->api_key }}'); alert('API Key copied to clipboard!');" style="background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); padding: 4px 10px; border-radius: 6px; font-size: 0.8rem; cursor: pointer;">Copy</button>
          @endif
        </div>

        <form action="{{ route('api.generate-key') }}" method="POST">
          @csrf
          <button type="submit" style="width: 100%; padding: 0.9rem; background: linear-gradient(135deg, #6366f1 0%, #d946ef 100%); color: #fff; border: none; border-radius: 12px; font-weight: 800; font-size: 0.95rem; cursor: pointer; box-shadow: 0 4px 20px rgba(99, 102, 241, 0.35);">
            ⚡ Generate New API Key
          </button>
        </form>
      </div>

    </div>

  </main>
</div>
@endsection
