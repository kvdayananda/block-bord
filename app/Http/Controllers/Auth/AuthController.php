<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Models\EmailVerificationToken;
use App\Models\PasswordResetToken;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;
use Carbon\Carbon;

class AuthController extends Controller
{
    private function validatePasswordStrength(string $password): ?string
    {
        if (strlen($password) < 12) {
            return "Password must be at least 12 characters long.";
        }
        if (!preg_match('/[A-Z]/', $password)) {
            return "Password must contain at least one uppercase letter.";
        }
        if (!preg_match('/[a-z]/', $password)) {
            return "Password must contain at least one lowercase letter.";
        }
        if (!preg_match('/[0-9]/', $password)) {
            return "Password must contain at least one number.";
        }
        if (!preg_match('/[!@#$%^&*()_+\-=\[\]{}|;:\'",.\/<>?`~]/', $password)) {
            return "Password must contain at least one special character.";
        }
        return null;
    }

    public function showRegister()
    {
        return view('auth.register');
    }

    public function register(Request $request)
    {
        $request->validate([
            'username' => 'required|string|max:191|unique:users,username',
            'email' => 'required|email|max:191|unique:users,email',
            'password' => 'required|string',
        ]);

        $pwdError = $this->validatePasswordStrength($request->password);
        if ($pwdError) {
            return back()->withInput()->with('error', $pwdError);
        }

        $user = User::create([
            'username' => trim($request->username),
            'email' => strtolower(trim($request->email)),
            'password' => Hash::make($request->password),
            'is_active' => true,
            'is_email_verified' => false,
            'is_pro' => false,
            'plan' => 'free',
        ]);

        // Generate verification token
        $token = Str::random(64);
        EmailVerificationToken::create([
            'token' => $token,
            'user_id' => $user->id,
            'expires_at' => Carbon::now()->addHours(24),
            'used' => false,
        ]);

        Auth::login($user);

        return redirect()->route('dashboard')->with('success', 'Registration successful! Welcome to Block Bord AI.');
    }

    public function showLogin()
    {
        return view('auth.login');
    }

    public function login(Request $request)
    {
        $credentials = $request->validate([
            'email' => 'required|string',
            'password' => 'required|string',
        ]);

        $loginType = filter_var($credentials['email'], FILTER_VALIDATE_EMAIL) ? 'email' : 'username';

        if (Auth::attempt([$loginType => $credentials['email'], 'password' => $credentials['password']], $request->filled('remember'))) {
            $request->session()->regenerate();
            $user = Auth::user();

            if ($user->totp_enabled) {
                session(['totp_passed' => false]);
                return redirect()->route('auth.verify_2fa');
            }

            return redirect()->intended(route('dashboard'));
        }

        return back()->withInput()->with('error', 'Invalid email/username or password.');
    }

    public function logout(Request $request)
    {
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return redirect()->route('landing')->with('success', 'Logged out successfully.');
    }

    public function showForgotPassword()
    {
        return view('auth.forgot_password');
    }

    public function sendResetLink(Request $request)
    {
        $request->validate(['email' => 'required|email']);
        $user = User::where('email', strtolower(trim($request->email)))->first();

        if ($user) {
            $token = Str::random(64);
            PasswordResetToken::create([
                'token' => $token,
                'user_id' => $user->id,
                'expires_at' => Carbon::now()->addHours(2),
                'used' => false,
            ]);
            // Send mail logic attached in Email phase
        }

        return back()->with('success', 'If your email exists in our system, a password reset link has been dispatched.');
    }

    public function showResetPassword(string $token)
    {
        $tokenRecord = PasswordResetToken::where('token', $token)
            ->where('used', false)
            ->where('expires_at', '>', Carbon::now())
            ->first();

        if (!$tokenRecord) {
            return redirect()->route('login')->with('error', 'Invalid or expired password reset token.');
        }

        return view('auth.reset_password', ['token' => $token]);
    }

    public function resetPassword(Request $request, string $token)
    {
        $request->validate(['password' => 'required|string']);

        $tokenRecord = PasswordResetToken::where('token', $token)
            ->where('used', false)
            ->where('expires_at', '>', Carbon::now())
            ->first();

        if (!$tokenRecord) {
            return redirect()->route('login')->with('error', 'Invalid or expired password reset token.');
        }

        $pwdError = $this->validatePasswordStrength($request->password);
        if ($pwdError) {
            return back()->with('error', $pwdError);
        }

        $user = $tokenRecord->user;
        $user->password = Hash::make($request->password);
        $user->save();

        $tokenRecord->used = true;
        $tokenRecord->save();

        return redirect()->route('login')->with('success', 'Password reset successful! Please log in with your new password.');
    }

    public function verifyEmail(string $token)
    {
        $tokenRecord = EmailVerificationToken::where('token', $token)
            ->where('used', false)
            ->where('expires_at', '>', Carbon::now())
            ->first();

        if (!$tokenRecord) {
            return redirect()->route('dashboard')->with('error', 'Invalid or expired verification token.');
        }

        $user = $tokenRecord->user;
        $user->is_email_verified = true;
        $user->save();

        $tokenRecord->used = true;
        $tokenRecord->save();

        return redirect()->route('dashboard')->with('success', 'Email address verified successfully!');
    }

    public function generateApiKey(Request $request)
    {
        $user = Auth::user();
        if (!$user) {
            return response()->json(['success' => false, 'message' => 'Unauthenticated'], 401);
        }

        $apiKey = 'bb_' . Str::random(40);
        $user->api_key = $apiKey;
        $user->save();

        return response()->json(['success' => true, 'api_key' => $apiKey]);
    }

    public function revokeApiKey(Request $request)
    {
        $user = Auth::user();
        if (!$user) {
            return response()->json(['success' => false, 'message' => 'Unauthenticated'], 401);
        }

        $user->api_key = null;
        $user->save();

        return response()->json(['success' => true, 'message' => 'API Key revoked successfully']);
    }
}
