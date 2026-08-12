@extends('layouts.app')
@section('title', 'Admin Blacklist — Block Bord AI')
@section('content')
<div style="display: flex; min-height: calc(100vh - 70px);">
  <x-sidebar />
  <main style="flex: 1; padding: 2.5rem; background: #0f0f17; color: #fff;">
    <h1 style="font-size: 2rem; font-weight: 800; margin-bottom: 1.5rem;">Global Blacklist Management</h1>
    
    <div style="background: #1e1e2e; padding: 1.5rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08); margin-bottom: 2rem; max-width: 500px;">
      <h3 style="font-size: 1.1rem; font-weight: 700; margin-bottom: 1rem;">Add Domain to Blacklist</h3>
      <form action="{{ route('admin.blacklist') }}" method="POST">
        @csrf
        <input type="text" name="domain" placeholder="malicious-domain.com" required style="width: 100%; padding: 0.75rem; border-radius: 8px; border: 1px solid #33334d; background: #11111b; color: #fff; margin-bottom: 1rem;">
        <input type="text" name="reason" placeholder="Reason (e.g. Known Phishing)" style="width: 100%; padding: 0.75rem; border-radius: 8px; border: 1px solid #33334d; background: #11111b; color: #fff; margin-bottom: 1rem;">
        <button type="submit" style="background: #ef4444; color: #fff; padding: 0.75rem 1.25rem; border: none; border-radius: 8px; font-weight: 700; cursor: pointer;">Add to Blacklist</button>
      </form>
    </div>

    <div style="background: #1e1e2e; border-radius: 12px; padding: 1.5rem; border: 1px solid rgba(255,255,255,0.08);">
      <table style="width: 100%; border-collapse: collapse; text-align: left;">
        <thead>
          <tr style="border-bottom: 1px solid #33334d; color: #94a3b8;">
            <th style="padding: 0.75rem;">Domain</th>
            <th style="padding: 0.75rem;">Reason</th>
            <th style="padding: 0.75rem;">Added At</th>
          </tr>
        </thead>
        <tbody>
          @foreach($domains as $item)
            <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
              <td style="padding: 0.75rem;">{{ $item->domain }}</td>
              <td style="padding: 0.75rem;">{{ $item->reason }}</td>
              <td style="padding: 0.75rem;">{{ $item->created_at->format('Y-m-d') }}</td>
            </tr>
          @endforeach
        </tbody>
      </table>
    </div>
  </main>
</div>
@endsection
