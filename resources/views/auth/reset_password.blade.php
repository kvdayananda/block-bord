@extends('layouts.app')

@section('title', 'Set New Password — Block Bord AI')

@section('content')
<div class="min-h-[80vh] flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8">
    <div class="max-w-md w-full space-y-8 bg-slate-900/80 p-8 rounded-2xl border border-slate-800 backdrop-blur-xl shadow-2xl">
        <div>
            <div class="flex justify-center">
                <span class="text-4xl">🔑</span>
            </div>
            <h2 class="mt-4 text-center text-3xl font-extrabold text-white">Create New Password</h2>
            <p class="mt-2 text-center text-sm text-slate-400">
                Please enter a strong password for your Block Bord AI account.
            </p>
        </div>

        @if (session('error'))
            <div class="p-4 bg-rose-500/10 border border-rose-500/30 rounded-xl text-rose-400 text-sm">
                {{ session('error') }}
            </div>
        @endif

        <form class="mt-8 space-y-6" action="{{ route('password.update', ['token' => $token]) }}" method="POST">
            @csrf
            <div>
                <label for="password" class="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2">New Password</label>
                <input id="password" name="password" type="password" required
                    class="w-full px-4 py-3 bg-slate-800/80 border border-slate-700 rounded-xl text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200"
                    placeholder="••••••••••••">
                <p class="mt-2 text-xs text-slate-400">Must be at least 12 characters with uppercase, lowercase, number, and symbol.</p>
            </div>

            <div>
                <button type="submit"
                    class="group relative w-full flex justify-center py-3.5 px-4 border border-transparent text-sm font-semibold rounded-xl text-white bg-blue-600 hover:bg-blue-500 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 shadow-lg shadow-blue-600/30 transition duration-200">
                    Update Password
                </button>
            </div>
        </form>
    </div>
</div>
@endsection
