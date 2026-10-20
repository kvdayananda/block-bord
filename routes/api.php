<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\ToolsController;
use App\Http\Controllers\AiAssistantController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
*/

Route::get('/health', function () {
    return response()->json(['status' => 'healthy']);
});

Route::prefix('v1')->group(function () {

    // Website Security
    Route::post('/scan/url', [ToolsController::class, 'scanUrl']);
    Route::post('/domain/inspect', [ToolsController::class, 'lookupDomain']);
    Route::post('/ip/lookup', [ToolsController::class, 'lookupIp']);
    Route::post('/ssl/check', [ToolsController::class, 'checkSsl']);
    Route::post('/headers/check', [ToolsController::class, 'checkHeaders']);
    Route::post('/tech/check', [ToolsController::class, 'checkTechnology']);
    Route::post('/redirects/check', [ToolsController::class, 'checkRedirects']);

    // Scam Protection
    Route::post('/scan/scam', [ToolsController::class, 'scanScam']);
    Route::post('/scan/phishing', [ToolsController::class, 'scanPhishing']);
    Route::post('/scan/email', [ToolsController::class, 'checkEmail']);
    Route::post('/scan/sms', [ToolsController::class, 'scanSms']);
    Route::post('/scan/qr', [ToolsController::class, 'scanQr']);
    Route::post('/phone/check', [ToolsController::class, 'checkPhoneNumber']);
    Route::post('/social/check', [ToolsController::class, 'checkSocialMedia']);

    // File & Content Security
    Route::post('/scan/file', [ToolsController::class, 'scanFile']);

    // Payment Protection
    Route::post('/scan/upi', [ToolsController::class, 'checkUpi']);

    // AI Endpoints
    Route::middleware(['auth'])->group(function () {
        Route::post('/ai/chat', [AiAssistantController::class, 'chat']);
        Route::post('/ai/analyze-risk', [AiAssistantController::class, 'analyzeScam']);
    });

    // Results & Reports
    Route::get('/scans', [ToolsController::class, 'listScans']);
    Route::get('/scans/{id}', [ToolsController::class, 'getScan']);
    Route::get('/reports/{id}', [ToolsController::class, 'getReport']);
    Route::get('/security-score', [ToolsController::class, 'getSecurityScore']);

    // Chrome Extension dedicated endpoints (supports API key auth via Bearer token)
    Route::post('/ext/scan', [ToolsController::class, 'extensionScan']);
    Route::get('/ext/status', [ToolsController::class, 'extensionStatus']);
});

// Extension backwards compatibility (session-based auth)
Route::post('/scan', [ToolsController::class, 'scanUrl']);
Route::post('/report', [ToolsController::class, 'reportUrl']);
Route::get('/ext/status', [ToolsController::class, 'extensionStatus']);
