@extends('layouts.app')

@section('title', 'Security Policy — Block Bord AI')

@section('content')
<div class="max-w-4xl mx-auto px-4 py-16 text-slate-300">
    <h1 class="text-3xl font-extrabold text-white mb-6">Security Policy</h1>

    <div class="space-y-6 text-sm leading-relaxed bg-slate-900/60 p-8 rounded-2xl border border-slate-800">
        <section>
            <h2 class="text-lg font-bold text-white mb-2">1. Encryption & Data Protection</h2>
            <p>Block Bord AI enforces TLS 1.3 encryption across all public web and API endpoints. User passwords are saved using strong Argon2id / Bcrypt password hashing. API keys are hashed and isolated.</p>
        </section>

        <section>
            <h2 class="text-lg font-bold text-white mb-2">2. Zero Plaintext Credentials Policy</h2>
            <p>Password checks utilize HaveIBeenPwned k-Anonymity SHA-1 prefix matching, ensuring your actual raw passwords never leave your browser or get logged on our infrastructure.</p>
        </section>

        <section>
            <h2 class="text-lg font-bold text-white mb-2">3. Infrastructure Isolation</h2>
            <p>Our machine learning prediction microservices run in isolated network environments without direct public internet exposure.</p>
        </section>
    </div>
</div>
@endsection
