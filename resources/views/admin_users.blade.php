@extends('layouts.app')
@section('title', 'Admin Users — Block Bord AI')
@section('content')
<div style="display: flex; min-height: calc(100vh - 70px);">
  <x-sidebar />
  <main style="flex: 1; padding: 2.5rem; background: #0f0f17; color: #fff;">
    <h1 style="font-size: 2rem; font-weight: 800; margin-bottom: 1.5rem;">User Management</h1>
    <div style="background: #1e1e2e; border-radius: 12px; padding: 1.5rem; border: 1px solid rgba(255,255,255,0.08);">
      <table style="width: 100%; border-collapse: collapse; text-align: left;">
        <thead>
          <tr style="border-bottom: 1px solid #33334d; color: #94a3b8;">
            <th style="padding: 0.75rem;">ID</th>
            <th style="padding: 0.75rem;">Username</th>
            <th style="padding: 0.75rem;">Email</th>
            <th style="padding: 0.75rem;">Plan</th>
            <th style="padding: 0.75rem;">Admin?</th>
          </tr>
        </thead>
        <tbody>
          @foreach($users as $user)
            <tr style="border-bottom: 1px solid rgba(255,255,255,0.05);">
              <td style="padding: 0.75rem;">{{ $user->id }}</td>
              <td style="padding: 0.75rem;">{{ $user->username }}</td>
              <td style="padding: 0.75rem;">{{ $user->email }}</td>
              <td style="padding: 0.75rem;"><span style="text-transform: uppercase; color: #818cf8; font-weight: 700;">{{ $user->plan }}</span></td>
              <td style="padding: 0.75rem;">{{ $user->is_admin ? 'Yes' : 'No' }}</td>
            </tr>
          @endforeach
        </tbody>
      </table>
      <div style="margin-top: 1rem;">{{ $users->links() }}</div>
    </div>
  </main>
</div>
@endsection
