@extends('layouts.app')
@section('title', 'Page Not Found — Block Bord AI')
@section('content')
<section style="padding: 6rem 1.5rem; text-align: center; color: #fff; min-height: 70vh; display: flex; flex-direction: column; justify-content: center; align-items: center;">
    <h1 style="font-size: 8rem; font-weight: 900; background: linear-gradient(135deg, #6366f1 0%, #d946ef 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin: 0; line-height: 1;">404</h1>
    <h2 style="font-size: 2rem; font-weight: 700; margin-top: 1rem; margin-bottom: 1.5rem;">Threat Not Found</h2>
    <p style="color: #94a3b8; font-size: 1.1rem; max-width: 500px; margin-bottom: 2.5rem;">
        The page you are looking for has been neutralized or does not exist. Let's get you back to safety.
    </p>
    <a href="{{ url('/') }}" style="padding: 1rem 2rem; background: #6366f1; color: white; border-radius: 12px; font-weight: 700; text-decoration: none; display: inline-flex; align-items: center; gap: 8px; transition: 0.3s ease;">
        <i class="fas fa-shield-alt"></i> Return to Safety
    </a>
</section>
@endsection
