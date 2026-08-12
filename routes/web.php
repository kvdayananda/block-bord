<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\PublicController;
use App\Http\Controllers\Auth\AuthController;
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\ToolsController;
use App\Http\Controllers\AiAssistantController;
use App\Http\Controllers\PaymentController;
use App\Http\Controllers\AdminController;

// ─── PUBLIC PAGES ──────────────────────────────────────────────
Route::get('/', [PublicController::class, 'landing'])->name('landing');
Route::get('/pricing', [PublicController::class, 'pricing'])->name('pricing');
Route::get('/about', [PublicController::class, 'about'])->name('about');
Route::get('/contact', [PublicController::class, 'contact'])->name('contact');
Route::get('/privacy', [PublicController::class, 'privacy'])->name('privacy');
Route::get('/terms', [PublicController::class, 'terms'])->name('terms');
Route::get('/cookie', [PublicController::class, 'cookie'])->name('cookie');
Route::get('/status', [PublicController::class, 'status'])->name('status');

// ─── AUTHENTICATION ─────────────────────────────────────────────
Route::get('/register', [AuthController::class, 'showRegister'])->name('register');
Route::post('/register', [AuthController::class, 'register']);
Route::get('/login', [AuthController::class, 'showLogin'])->name('login');
Route::post('/login', [AuthController::class, 'login']);
Route::get('/logout', [AuthController::class, 'logout'])->name('logout');

Route::get('/forgot-password', [AuthController::class, 'showForgotPassword'])->name('password.request');
Route::post('/forgot-password', [AuthController::class, 'sendResetLink'])->name('password.email');
Route::get('/reset-password/{token}', [AuthController::class, 'showResetPassword'])->name('password.reset');
Route::post('/reset-password/{token}', [AuthController::class, 'resetPassword'])->name('password.update');
Route::get('/verify-email/{token}', [AuthController::class, 'verifyEmail'])->name('verification.verify');

// ─── EXTENSION & BACKWARDS COMPATIBLE API ENDPOINTS ─────────────
Route::post('/scan', [ToolsController::class, 'scanUrl'])->name('scan');
Route::post('/report', [ToolsController::class, 'reportUrl'])->name('report');
Route::get('/api/ext/status', [ToolsController::class, 'extensionStatus'])->name('api.ext.status');

// ─── AUTHENTICATED USER ROUTES ──────────────────────────────────
Route::middleware(['auth'])->group(function () {
    Route::get('/app', [DashboardController::class, 'index'])->name('dashboard');
    Route::get('/history', [DashboardController::class, 'history'])->name('history');
    Route::get('/analytics', [DashboardController::class, 'analytics'])->name('analytics');
    Route::get('/settings', [DashboardController::class, 'settings'])->name('settings');
    Route::get('/extension-setup', [DashboardController::class, 'extensionSetup'])->name('extension.setup');
    Route::get('/block-list', [DashboardController::class, 'blockList'])->name('block_list');

    Route::post('/dashboard/api/generate_key', [AuthController::class, 'generateApiKey'])->name('api.generate-key');
    Route::post('/dashboard/api/revoke_key', [AuthController::class, 'revokeApiKey'])->name('api.revoke-key');

    // Payments
    Route::get('/checkout', [PaymentController::class, 'showCheckout'])->name('checkout');
    Route::post('/payments/create-order', [PaymentController::class, 'createOrder'])->name('payments.create-order');
    Route::post('/payments/verify', [PaymentController::class, 'verifyPayment'])->name('payments.verify');
});

// Webhook (Unprotected)
Route::post('/payments/webhook', [PaymentController::class, 'webhook'])->name('payments.webhook');

// ─── SECURITY & AI TOOLS ────────────────────────────────────────
Route::get('/tools', [ToolsController::class, 'home'])->name('tools.home');
Route::post('/tools/scan-url', [ToolsController::class, 'scanUrl'])->name('tools.scan-url');
Route::post('/tools/lookup-domain', [ToolsController::class, 'lookupDomain'])->name('tools.lookup-domain');
Route::post('/tools/lookup-ip', [ToolsController::class, 'lookupIp'])->name('tools.lookup-ip');
Route::post('/tools/check-password', [ToolsController::class, 'checkPassword'])->name('tools.check-password');
Route::post('/tools/check-ssl', [ToolsController::class, 'checkSsl'])->name('tools.check-ssl');

Route::get('/ai', [AiAssistantController::class, 'showAiPage'])->name('ai.page');
Route::post('/ai/chat', [AiAssistantController::class, 'chat'])->name('ai.chat');
Route::post('/tools/ai/api/scam', [AiAssistantController::class, 'analyzeScam'])->name('ai.scam');

// ─── ADMIN CONSOLE ──────────────────────────────────────────────
Route::middleware(['auth', 'admin'])->prefix('admin')->group(function () {
    Route::get('', [AdminController::class, 'dashboard'])->name('admin.dashboard');
    Route::get('/api/stats', [AdminController::class, 'stats'])->name('admin.stats');
    Route::get('/users', [AdminController::class, 'users'])->name('admin.users');
    Route::get('/blacklist', [AdminController::class, 'blacklist'])->name('admin.blacklist');
    Route::post('/blacklist', [AdminController::class, 'addBlacklist'])->name('admin.blacklist.add');
    Route::get('/whitelist', [AdminController::class, 'whitelist'])->name('admin.whitelist');
    Route::post('/whitelist', [AdminController::class, 'addWhitelist'])->name('admin.whitelist.add');
});
