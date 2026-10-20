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
Route::get('/features', [PublicController::class, 'features'])->name('features');
Route::get('/pricing', [PublicController::class, 'pricing'])->name('pricing');
Route::get('/about', [PublicController::class, 'about'])->name('about');
Route::get('/contact', [PublicController::class, 'contact'])->name('contact');
Route::get('/privacy', [PublicController::class, 'privacy'])->name('privacy');
Route::get('/terms', [PublicController::class, 'terms'])->name('terms');
Route::get('/cookie', [PublicController::class, 'cookie'])->name('cookie');
Route::get('/security-policy', [PublicController::class, 'securityPolicy'])->name('security.policy');
Route::get('/responsible-disclosure', [PublicController::class, 'responsibleDisclosure'])->name('responsible.disclosure');
Route::get('/faq', [PublicController::class, 'faq'])->name('faq');
Route::get('/status', [PublicController::class, 'status'])->name('status');
Route::get('/sitemap.xml', [PublicController::class, 'sitemap'])->name('sitemap');

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
Route::get('/email/verify', [AuthController::class, 'showVerifyEmailNotice'])->name('verification.notice');
Route::post('/email/verification-notification', [AuthController::class, 'resendVerificationEmail'])->name('verification.resend');

Route::get('/verify-2fa', [AuthController::class, 'show2faForm'])->name('auth.verify_2fa');
Route::post('/verify-2fa', [AuthController::class, 'verify2fa'])->name('auth.verify_2fa.post');

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
    Route::post('/settings/update', [DashboardController::class, 'updateSettings'])->name('settings.update');
    Route::get('/extension-setup', [DashboardController::class, 'extensionSetup'])->name('extension.setup');
    Route::get('/block-list', [DashboardController::class, 'blockList'])->name('block_list');

    Route::get('/reports', [DashboardController::class, 'reports'])->name('reports.index');
    Route::get('/reports/{id}', [DashboardController::class, 'reportDetail'])->name('reports.show');
    Route::get('/security-score', [DashboardController::class, 'securityScore'])->name('security.score');
    Route::get('/notifications', [DashboardController::class, 'notifications'])->name('notifications.index');
    Route::post('/notifications/{id}/read', [DashboardController::class, 'markNotificationRead'])->name('notifications.read');
    Route::post('/notifications/mark-all-read', [DashboardController::class, 'markAllNotificationsRead'])->name('notifications.markAllRead');
    Route::delete('/notifications/{id}', [DashboardController::class, 'deleteNotification'])->name('notifications.delete');
    Route::get('/subscription', [DashboardController::class, 'subscription'])->name('subscription');

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
Route::post('/tools/check-email', [ToolsController::class, 'checkEmail'])->name('tools.check-email');
Route::post('/tools/check-upi', [ToolsController::class, 'checkUpi'])->name('tools.check-upi');

Route::middleware(['auth'])->group(function () {
    Route::get('/ai', [AiAssistantController::class, 'showAiPage'])->name('ai.page');
    Route::post('/ai/chat', [AiAssistantController::class, 'chat'])->name('ai.chat');
    Route::get('/ai/conversation/{id}', [AiAssistantController::class, 'getConversation'])->name('ai.conversation.get');
    Route::delete('/ai/conversation/{id}', [AiAssistantController::class, 'deleteConversation'])->name('ai.conversation.delete');
    Route::post('/tools/ai/api/scam', [AiAssistantController::class, 'analyzeScam'])->name('ai.scam');
});

// ─── ADMIN CONSOLE ──────────────────────────────────────────────
Route::middleware(['auth', 'admin'])->prefix('admin')->group(function () {
    Route::get('', [AdminController::class, 'dashboard'])->name('admin.dashboard');
    Route::get('/api/stats', [AdminController::class, 'stats'])->name('admin.stats');

    // 1. Users Management
    Route::get('/users', [AdminController::class, 'users'])->name('admin.users');
    Route::post('/users/{id}/toggle-status', [AdminController::class, 'toggleUserStatus'])->name('admin.users.toggle-status');
    Route::post('/users/{id}/plan', [AdminController::class, 'updateUserPlan'])->name('admin.users.update-plan');
    Route::post('/users/{id}/toggle-admin', [AdminController::class, 'toggleUserAdmin'])->name('admin.users.toggle-admin');

    // 2. Scans Management
    Route::get('/scans', [AdminController::class, 'scans'])->name('admin.scans');
    Route::delete('/scans/{id}', [AdminController::class, 'deleteScan'])->name('admin.scans.delete');

    // 3. Threats & User Reports
    Route::get('/threats', [AdminController::class, 'threats'])->name('admin.threats');
    Route::post('/threats/reports/{id}/resolve', [AdminController::class, 'resolveReport'])->name('admin.threats.resolve');

    // 4. Blacklist & Whitelist
    Route::get('/blacklist', [AdminController::class, 'blacklist'])->name('admin.blacklist');
    Route::post('/blacklist', [AdminController::class, 'addBlacklist'])->name('admin.blacklist.add');
    Route::delete('/blacklist/{id}', [AdminController::class, 'deleteBlacklist'])->name('admin.blacklist.delete');
    Route::get('/whitelist', [AdminController::class, 'whitelist'])->name('admin.whitelist');
    Route::post('/whitelist', [AdminController::class, 'addWhitelist'])->name('admin.whitelist.add');
    Route::delete('/whitelist/{id}', [AdminController::class, 'deleteWhitelist'])->name('admin.whitelist.delete');

    // 5. Payments & Subscriptions
    Route::get('/payments', [AdminController::class, 'payments'])->name('admin.payments');

    // 6. AI & API Usage
    Route::get('/api-usage', [AdminController::class, 'apiUsage'])->name('admin.api-usage');

    // 7. System Logs & Cache
    Route::get('/logs', [AdminController::class, 'logs'])->name('admin.logs');
    Route::post('/clear-cache', [AdminController::class, 'clearCache'])->name('admin.clear-cache');
});
