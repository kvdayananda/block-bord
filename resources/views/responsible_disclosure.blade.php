@extends('layouts.app')

@section('title', 'Responsible Disclosure — Block Bord AI')

@section('content')
<div class="max-w-4xl mx-auto px-4 py-16 text-slate-300">
    <h1 class="text-3xl font-extrabold text-white mb-6">Responsible Disclosure Program</h1>

    <div class="space-y-6 text-sm leading-relaxed bg-slate-900/60 p-8 rounded-2xl border border-slate-800">
        <p>We take the security of Block Bord AI seriously. If you believe you have discovered a vulnerability in our application or extension, please report it to us responsibly.</p>

        <section>
            <h2 class="text-lg font-bold text-white mb-2">Reporting Guidelines</h2>
            <ul class="list-disc pl-5 space-y-2 text-slate-400">
                <li>Email your findings to <strong class="text-white">security@blockbord.com</strong>.</li>
                <li>Provide step-by-step reproduction instructions or proof-of-concept code.</li>
                <li>Allow us reasonable time to resolve the issue before public disclosure.</li>
                <li>Do not access or modify user data without permission.</li>
            </ul>
        </section>
    </div>
</div>
@endsection
