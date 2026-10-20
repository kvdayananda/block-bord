@extends('layouts.app')

@section('title', 'Frequently Asked Questions — Block Bord AI')

@section('content')
<div class="max-w-4xl mx-auto px-4 py-16 text-slate-300">
    <h1 class="text-3xl font-extrabold text-white mb-6">Frequently Asked Questions</h1>

    <div class="space-y-6 bg-slate-900/60 p-8 rounded-2xl border border-slate-800">
        <div>
            <h3 class="text-lg font-bold text-white mb-2">How does Block Bord AI calculate risk scores?</h3>
            <p class="text-sm text-slate-400">Our security engine blends trained XGBoost machine learning probability models, Google Safe Browsing threat databases, domain WHOIS telemetry, SSL handshake validation, and structural pattern heuristics.</p>
        </div>

        <div>
            <h3 class="text-lg font-bold text-white mb-2">Is Block Bord AI 100% accurate?</h3>
            <p class="text-sm text-slate-400">No security system can guarantee 100% detection of zero-day threats. Block Bord AI provides high-probability security intelligence and transparent explanations to help you make safer decisions before trusting digital content.</p>
        </div>

        <div>
            <h3 class="text-lg font-bold text-white mb-2">How does the Chrome Extension work?</h3>
            <p class="text-sm text-slate-400">The Chrome Extension operates locally in your browser using Manifest V3 service workers, evaluating page URLs against risk signals and alerting you before you submit sensitive information on flagged domains.</p>
        </div>
    </div>
</div>
@endsection
