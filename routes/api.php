<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\ToolsController;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
*/

// Health Check Endpoint
Route::get('/health', function () {
    return response()->json(['status' => 'healthy']);
});

Route::post('/scan', [ToolsController::class, 'scanUrl']);
Route::post('/report', [ToolsController::class, 'reportUrl']);
Route::get('/ext/status', [ToolsController::class, 'extensionStatus']);
