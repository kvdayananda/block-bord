<?php

namespace App\Http\Controllers;

use App\Services\Security\SecurityToolService;
use App\Services\ML\MLService;
use App\Services\Security\ReportService;
use App\Services\Security\ClamAvScanner;
use App\Services\SecurityScoreService;
use App\Services\Security\UniversalRiskEngine;
use App\Models\ScanHistory;
use App\Models\UserReport;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Carbon;
use Symfony\Component\Process\Process;

class ToolsController extends Controller
{
    protected SecurityToolService $securityService;
    protected MLService $mlService;
    protected ReportService $reportService;
    protected SecurityScoreService $scoreService;
    protected UniversalRiskEngine $riskEngine;
    protected ClamAvScanner $clamAvScanner;

    public function __construct(
        SecurityToolService $securityService,
        MLService $mlService,
        ReportService $reportService,
        SecurityScoreService $scoreService,
        UniversalRiskEngine $riskEngine,
        ClamAvScanner $clamAvScanner
    ) {
        $this->securityService = $securityService;
        $this->mlService = $mlService;
        $this->reportService = $reportService;
        $this->scoreService = $scoreService;
        $this->riskEngine = $riskEngine;
        $this->clamAvScanner = $clamAvScanner;
    }

    public function home()
    {
        return view('tools');
    }

    public function scanUrl(Request $request)
    {
        $target = $request->input('url') ?? $request->input('content') ?? $request->input('target');
        if (!$target) {
            return response()->json(['success' => false, 'message' => 'Input parameter required'], 400);
        }

        // Evaluate via Universal Risk Engine with strict weights & risk bands
        $result = $this->riskEngine->evaluate($target);

        // Store scan history
        $scanRecord = ScanHistory::create([
            'content' => $result['normalized_target'] ?? $target,
            'url_hash' => $result['url_hash'],
            'risk_score' => $result['risk_score'],
            'risk_level' => $result['risk_level'],
            'reasons' => json_encode($result['evidence']),
            'category' => $result['input_type'] ?? 'url',
            'scam_intent' => $result['scam_intent'] ?? 'Informational',
            'user_id' => Auth::id(),
        ]);

        $result['scan_id'] = $scanRecord->id;

        // Extension requests get a flat response matching the extension's expected contract
        if ($request->header('X-BlockBord-Source') === 'extension') {
            return response()->json([
                'risk_score'  => $result['risk_score'],
                'risk_level'  => $result['risk_level'],
                'category'    => $result['input_type'] ?? 'url',
                'reasons'     => $result['evidence'] ?? [],
                'scan_id'     => $scanRecord->id,
                'scam_intent' => $result['scam_intent'] ?? 'Informational',
            ]);
        }

        if ($request->expectsJson() || $request->is('api/*') || $request->is('scan')) {
            return response()->json([
                'success' => true,
                'data' => $result,
                'message' => 'Inspection completed successfully',
            ]);
        }

        return redirect()->route('reports.show', ['id' => $scanRecord->id]);
    }

    public function lookupDomain(Request $request)
    {
        $domain = $request->input('domain', 'example.com');
        $result = $this->securityService->lookupDomain($domain);
        return response()->json(['success' => true, 'data' => $result]);
    }

    public function lookupIp(Request $request)
    {
        $ip = $request->input('ip', $request->ip());
        $result = $this->securityService->lookupIp($ip);
        return response()->json(['success' => true, 'data' => $result]);
    }

    public function checkPassword(Request $request)
    {
        $password = $request->input('password', '');
        $result = $this->securityService->checkPassword($password);
        return response()->json(['success' => true, 'data' => $result]);
    }

    public function checkSsl(Request $request)
    {
        $domain = $request->input('domain', 'example.com');
        $result = $this->securityService->checkSsl($domain);
        return response()->json(['success' => true, 'data' => $result]);
    }

    public function checkEmail(Request $request)
    {
        $headers = $request->input('headers', '');
        $result = $this->securityService->checkEmailHeader($headers);
        return response()->json(['success' => true, 'data' => $result]);
    }

    public function checkUpi(Request $request)
    {
        $query = $request->input('query', '');
        $result = $this->securityService->checkUpiScam($query);
        return response()->json(['success' => true, 'data' => $result]);
    }

    public function checkHeaders(Request $request)
    {
        $url = $request->input('url');
        if (!$url) return response()->json(['success' => false, 'message' => 'URL required'], 400);
        $result = $this->securityService->checkHeaders($url);
        return response()->json(['success' => true, 'data' => $result]);
    }

    public function checkTechnology(Request $request)
    {
        $url = $request->input('url');
        if (!$url) return response()->json(['success' => false, 'message' => 'URL required'], 400);
        $result = $this->securityService->checkTechnology($url);
        return response()->json(['success' => true, 'data' => $result]);
    }

    public function checkRedirects(Request $request)
    {
        $url = $request->input('url');
        if (!$url) return response()->json(['success' => false, 'message' => 'URL required'], 400);
        $result = $this->securityService->checkRedirects($url);
        return response()->json(['success' => true, 'data' => $result]);
    }

    public function checkPhoneNumber(Request $request)
    {
        $phone = $request->input('phone');
        if (!$phone) return response()->json(['success' => false, 'message' => 'Phone number required'], 400);
        $result = $this->securityService->checkPhoneNumber($phone);
        return response()->json(['success' => true, 'data' => $result]);
    }

    public function checkSocialMedia(Request $request)
    {
        $input = $request->input('input');
        if (!$input) return response()->json(['success' => false, 'message' => 'Input required'], 400);
        $result = $this->securityService->checkSocialMediaScam($input);
        return response()->json(['success' => true, 'data' => $result]);
    }

    public function scanQr(Request $request)
    {
        $image = $request->file('qr_image') ?? $request->file('image');
        if (!$image) {
            return response()->json(['success' => false, 'message' => 'QR image is required'], 422);
        }

        $request->validate([
            'qr_image' => ['sometimes', 'file', 'mimes:jpg,jpeg,png,webp', 'max:10240'],
            'image' => ['sometimes', 'file', 'mimes:jpg,jpeg,png,webp', 'max:10240'],
        ]);

        try {
            $process = new Process([
                config('services.qr_decoder.binary'),
                '--quiet',
                '--raw',
                $image->getRealPath(),
            ]);
            $process->setTimeout(15);
            $process->run();
        } catch (\RuntimeException $exception) {
            return response()->json([
                'success' => false,
                'message' => 'QR decoder is unavailable',
            ], 503);
        }

        if (!$process->isSuccessful()) {
            return response()->json([
                'success' => false,
                'message' => 'No readable QR code was found in the image',
            ], 422);
        }

        $decodedValues = array_values(array_filter(array_map('trim', preg_split('/\R/', $process->getOutput()))));
        if (count($decodedValues) !== 1) {
            return response()->json([
                'success' => false,
                'message' => $decodedValues
                    ? 'The image must contain exactly one QR code'
                    : 'No readable QR code was found in the image',
            ], 422);
        }

        $request->merge(['url' => $decodedValues[0]]);
        return $this->scanUrl($request);
    }

    public function scanScam(Request $request)
    {
        return $this->scanUrl($request);
    }

    public function scanPhishing(Request $request)
    {
        return $this->scanUrl($request);
    }

    public function scanSms(Request $request)
    {
        return $this->scanUrl($request);
    }

    public function scanFile(Request $request)
    {
        $validated = $request->validate([
            'file' => ['required', 'file', 'max:20480'],
        ]);
        $file = $validated['file'];

        try {
            $scanResult = $this->clamAvScanner->scan($file->getRealPath());
        } catch (\RuntimeException $exception) {
            Log::warning('ClamAV file scan unavailable.', ['message' => $exception->getMessage()]);
            return response()->json([
                'success' => false,
                'message' => 'Malware scanner is unavailable; the file was not classified',
            ], 503);
        }

        $riskScore = $scanResult['infected'] ? 100 : 0;
        $fileHash = hash_file('sha256', $file->getRealPath());
        if ($fileHash === false) {
            return response()->json(['success' => false, 'message' => 'Could not calculate file hash'], 500);
        }
        $record = \App\Models\FileScan::create([
            'user_id' => Auth::id(),
            'file_hash' => $fileHash,
            'file_name' => mb_substr(basename($file->getClientOriginalName()), 0, 255),
            'risk_score' => $riskScore,
        ]);

        return response()->json([
            'success' => true,
            'data' => [
                'scan_id' => $record->id,
                'file_hash' => $fileHash,
                'status' => $scanResult['infected'] ? 'infected' : 'clean',
                'risk_score' => $riskScore,
                'threat' => $scanResult['threat'],
            ],
        ]);
    }

    public function listScans(Request $request)
    {
        $user = Auth::user();
        if (!$user) {
            return response()->json(['success' => false, 'message' => 'Unauthenticated'], 401);
        }
        $scans = ScanHistory::where('user_id', $user->id)
            ->orderBy('created_at', 'desc')
            ->take(30)
            ->get();

        return response()->json([
            'success' => true,
            'data' => $scans,
        ]);
    }

    public function getScan($id)
    {
        $user = Auth::user();
        if (!$user) {
            return response()->json(['success' => false, 'message' => 'Unauthenticated'], 401);
        }

        $scan = ScanHistory::where('user_id', $user->id)->find($id);
        if (!$scan) {
            return response()->json(['success' => false, 'message' => 'Scan not found'], 404);
        }

        return response()->json([
            'success' => true,
            'data' => $scan,
        ]);
    }

    public function getReport($id)
    {
        $user = Auth::user();
        if (!$user) {
            return response()->json(['success' => false, 'message' => 'Unauthenticated'], 401);
        }

        $scan = ScanHistory::where('user_id', $user->id)->find($id);
        if (!$scan) {
            return response()->json(['success' => false, 'message' => 'Report not found'], 404);
        }

        $reportData = $this->reportService->generateReportData($scan);

        return response()->json([
            'success' => true,
            'data' => $reportData,
        ]);
    }

    public function getSecurityScore(Request $request)
    {
        $user = Auth::user();
        if ($user) {
            $scoreData = $this->scoreService->calculate($user);
            return response()->json(['success' => true, 'data' => $scoreData]);
        }

        return response()->json([
            'success' => true,
            'data' => [
                'score' => 95,
                'grade' => 'A',
                'rating' => 'Baseline Protection',
            ]
        ]);
    }

    public function reportUrl(Request $request)
    {
        $url = $request->input('url');
        if (!$url) {
            return response()->json(['success' => false, 'message' => 'Reported URL is required'], 400);
        }

        UserReport::create([
            'reported_url' => $url,
            'reported_domain' => parse_url($url, PHP_URL_HOST) ?? $url,
            'description' => $request->input('description', 'User flagged via extension/form'),
            'status' => 'pending',
            'user_id' => Auth::id(),
        ]);

        return response()->json(['success' => true, 'message' => 'Report submitted successfully']);
    }

    public function extensionStatus(Request $request)
    {
        // Support API key auth: check Authorization header first
        $user = Auth::user();
        if (!$user) {
            $user = $this->resolveUserFromApiKey($request);
        }

        $scansToday = 0;
        $scanLimit = 5; // Free tier default
        if ($user) {
            $scansToday = ScanHistory::where('user_id', $user->id)
                ->whereDate('created_at', Carbon::today())
                ->count();
            $scanLimit = $user->is_pro ? 500 : ($user->plan === 'business' ? 9999 : 5);
        }

        return response()->json([
            'success'       => true,
            'authenticated' => (bool)$user,
            'logged_in'     => (bool)$user,
            'username'      => $user->username ?? null,
            'plan'          => $user->plan ?? 'free',
            'is_pro'        => $user->is_pro ?? false,
            'scans_today'   => $scansToday,
            'scan_limit'    => $scanLimit,
        ]);
    }

    /**
     * Extension-specific scan endpoint with API key authentication.
     * Accepts Bearer token in Authorization header.
     */
    public function extensionScan(Request $request)
    {
        // Authenticate via API key if no session user
        $user = Auth::user();
        if (!$user) {
            $user = $this->resolveUserFromApiKey($request);
            if ($user) {
                Auth::login($user); // Temporarily set auth for downstream services
            }
        }

        // Ensure extension header is set for flat response
        $request->headers->set('X-BlockBord-Source', 'extension');
        return $this->scanUrl($request);
    }

    /**
     * Resolve a User from an API key in the Authorization: Bearer header.
     */
    protected function resolveUserFromApiKey(Request $request): ?User
    {
        $bearer = $request->bearerToken();
        if (!$bearer) {
            return null;
        }

        // API keys stored as api_key column on users table
        return User::where('api_key', $bearer)->first();
    }
}
