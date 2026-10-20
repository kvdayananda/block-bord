@extends('layouts.app')

@section('title', 'Verify Your Email - Block Bord AI')

@section('content')
<div class="min-h-screen bg-gray-50 flex flex-col justify-center py-12 sm:px-6 lg:px-8">
    <div class="sm:mx-auto sm:w-full sm:max-w-md">
        <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900">
            Check Your Email
        </h2>
        <p class="mt-2 text-center text-sm text-gray-600">
            We've sent a verification link to your email address.
        </p>
    </div>

    <div class="mt-8 sm:mx-auto sm:w-full sm:max-w-md">
        <div class="bg-white py-8 px-4 shadow sm:rounded-lg sm:px-10 text-center">

            <svg class="mx-auto h-12 w-12 text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
            </svg>

            <p class="mt-4 text-gray-700">
                Please click the link in the email to verify your account and gain full access to the Block Bord AI dashboard.
            </p>

            <div class="mt-6">
                <form action="{{ route('verification.resend') }}" method="POST">
                    @csrf
                    <button type="submit" class="w-full flex justify-center py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
                        Resend Verification Email
                    </button>
                </form>
            </div>

            <div class="mt-4">
                <a href="{{ route('dashboard') }}" class="text-sm font-medium text-blue-600 hover:text-blue-500">
                    Go to Dashboard anyway
                </a>
            </div>

        </div>
    </div>
</div>
@endsection
