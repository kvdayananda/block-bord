@extends('layouts.app')
@section('title', 'System Error — Block Bord AI')
@section('content')
<section style="padding: 6rem 1.5rem; text-align: center; color: #fff; min-height: 70vh; display: flex; flex-direction: column; justify-content: center; align-items: center;">
    <h1 style="font-size: 8rem; font-weight: 900; background: linear-gradient(135deg, #ef4444 0%, #f59e0b 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin: 0; line-height: 1;">500</h1>
    <h2 style="font-size: 2rem; font-weight: 700; margin-top: 1rem; margin-bottom: 1.5rem;">System Overload</h2>
    <p style="color: #94a3b8; font-size: 1.1rem; max-width: 500px; margin-bottom: 2.5rem;">
        Our AI neural net encountered an unexpected anomaly. Our security engineers have been automatically notified.
    </p>
    <a href="{{ url('/') }}" style="padding: 1rem 2rem; background: #1e293b; color: white; border-radius: 12px; border: 1px solid rgba(255,255,255,0.1); font-weight: 700; text-decoration: none; display: inline-flex; align-items: center; gap: 8px; transition: 0.3s ease;">
        <i class="fas fa-home"></i> Back to Safety
    </a>
</section>
@endsection
