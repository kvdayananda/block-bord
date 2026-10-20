@extends('layouts.app')

@section('title', 'Verify Two-Factor Authentication - Block Bord AI')

@section('content')
<div class="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
    <div class="sm:mx-auto sm:w-full sm:max-w-md">
        <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900">
            Two-Factor Authentication
        </h2>
        <p class="mt-2 text-center text-sm text-gray-600">
            Enter the 6-digit code from your authenticator app.
        </p>
    </div>

    <div class="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div class="bg-white py-8 px-4 shadow sm:rounded-lg sm:px-10">

            @if (session('error'))
                <div class="mb-4 bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded relative" role="alert">
                    <span class="block sm:inline">{{ session('error') }}</span>
                </div>
            @endif

            <form class="space-y-6" action="{{ route('auth.verify_2fa.post') }}" method="POST">
                @csrf
                <div>
                    <label for="totp_code" class="block text-sm font-medium text-gray-700">
                        Authentication Code
                    </label>
                    <div class="mt-1">
                        <input id="totp_code" name="totp_code" type="text" autocomplete="off" required autofocus
                            class="appearance-none block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm placeholder-gray-400 focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm text-center text-2xl tracking-widest">
                    </div>
                </div>

                <div>
                    <button type="submit"
                        class="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                        Verify Code
                    </button>
                </div>
            </form>

            <div class="mt-6">
                <div class="relative">
                    <div class="relative flex justify-center text-sm">
                        <span class="px-2 bg-white text-gray-500">
                            Having trouble?
                        </span>
                    </div>
                </div>
                <div class="mt-6 grid grid-cols-1 gap-3">
                    <a href="{{ route('logout') }}" class="w-full flex justify-center py-2 px-4 border border-gray-300 rounded-md shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50">
                        Cancel and Log Out
                    </a>
                </div>
            </div>

        </div>
    </div>
</div>
@endsection
