<?php

namespace App\Http\Controllers;

use App\Services\Security\SecurityToolService;
use App\Services\ML\MLService;
use App\Models\ScanHistory;
use App\Models\UserReport;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class ToolsController extends Controller
{
    protected SecurityToolService $securityService;
    protected MLService $mlService;

    public function __construct(SecurityToolService $securityService, MLService $mlService)
    {
        $this->securityService = $securityService;
        $this->mlService = $mlService;
    }

    public function home()
    {
        return view('tools');
    }

    public function scanUrl(Request $request)
    {
        $targetUrl = $request->input('url') ?? $request->input('content');
        if (!$targetUrl) {
            return response()->json(['success' => false, 'message' => 'URL parameter required'], 400);
        }

        $result = $this->securityService->scanUrl($targetUrl);

        // Fetch ML prediction score
        $mlResult = $this->mlService->predictScamScore($targetUrl, $targetUrl);
        $combinedScore = round(($result['risk_score'] * 0.5) + ($mlResult['probability'] * 100 * 0.5), 2);
        $result['risk_score'] = $combinedScore;
        $result['risk_level'] = $combinedScore >= 70 ? 'high' : ($combinedScore >= 35 ? 'medium' : 'safe');

        // Store scan history
        ScanHistory::create([
            'content' => $targetUrl,
            'url_hash' => $result['url_hash'],
            'risk_score' => $result['risk_score'],
            'risk_level' => $result['risk_level'],
            'reasons' => json_encode($result['reasons']),
            'category' => 'url',
            'scam_intent' => $result['scam_intent'],
            'user_id' => Auth::id(),
        ]);

        if ($request->expectsJson() || $request->is('api/*') || $request->is('scan')) {
            return response()->json([
                'success' => true,
                'data' => $result,
                'message' => 'URL scanned successfully',
            ]);
        }

        return view('scan_detail', ['scan' => $result]);
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
        $user = Auth::user();
        return response()->json([
            'success' => true,
            'authenticated' => (bool)$user,
            'username' => $user ? $user->username : null,
            'plan' => $user ? $user->plan : 'free',
            'is_pro' => $user ? $user->is_pro : false,
        ]);
    }
}
