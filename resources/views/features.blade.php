@extends('layouts.app')

@section('title', 'Platform Features — Block Bord AI')

@section('content')
<div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-16">
    <div class="text-center max-w-3xl mx-auto mb-16">
        <h1 class="text-4xl sm:text-5xl font-extrabold text-white tracking-tight">
            AI-Powered Digital Safety Engine
        </h1>
        <p class="mt-4 text-xl text-slate-400">
            Comprehensive multi-layered intelligence protecting you from digital fraud, phishing links, identity theft, and malicious code.
        </p>
    </div>

    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
        <div class="bg-slate-900/60 border border-slate-800 p-8 rounded-2xl">
            <div class="text-3xl mb-4">🔍</div>
            <h3 class="text-xl font-bold text-white mb-2">Real-Time URL Scanner</h3>
            <p class="text-slate-400 text-sm">Blends XGBoost machine learning models, Google Safe Browsing APIs, and heuristic threat signatures to evaluate suspicious links.</p>
        </div>

        <div class="bg-slate-900/60 border border-slate-800 p-8 rounded-2xl">
            <div class="text-3xl mb-4">🤖</div>
            <h3 class="text-xl font-bold text-white mb-2">AI Scam Assistant</h3>
            <p class="text-slate-400 text-sm">Powered by Google Gemini and OpenAI with automatic fallback, providing clear, human-understandable risk explanations.</p>
        </div>

        <div class="bg-slate-900/60 border border-slate-800 p-8 rounded-2xl">
            <div class="text-3xl mb-4">🔒</div>
            <h3 class="text-xl font-bold text-white mb-2">SSL Certificate Inspector</h3>
            <p class="text-slate-400 text-sm">Validates SSL socket handshakes, certificate authority chains, expiration countdowns, and cipher suite security.</p>
        </div>

        <div class="bg-slate-900/60 border border-slate-800 p-8 rounded-2xl">
            <div class="text-3xl mb-4">🌐</div>
            <h3 class="text-xl font-bold text-white mb-2">Domain & IP Telemetry</h3>
            <p class="text-slate-400 text-sm">Extract WHOIS registration age, DNS records, hosting ISP geolocation, and proxy/anonymizer indicators.</p>
        </div>

        <div class="bg-slate-900/60 border border-slate-800 p-8 rounded-2xl">
            <div class="text-3xl mb-4">🔐</div>
            <h3 class="text-xl font-bold text-white mb-2">Password Breach Checker</h3>
            <p class="text-slate-400 text-sm">Uses k-Anonymity SHA-1 prefix matching to verify whether passwords have appeared in public data breaches.</p>
        </div>

        <div class="bg-slate-900/60 border border-slate-800 p-8 rounded-2xl">
            <div class="text-3xl mb-4">🧩</div>
            <h3 class="text-xl font-bold text-white mb-2">Chrome Extension</h3>
            <p class="text-slate-400 text-sm">Manifest V3 background worker providing proactive warnings before you visit dangerous websites or enter credentials.</p>
        </div>
    </div>
</div>
@endsection
