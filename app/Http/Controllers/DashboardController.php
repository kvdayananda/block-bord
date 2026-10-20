<?php

namespace App\Http\Controllers;

use App\Models\ScanHistory;
use App\Models\BlacklistDomain;
use App\Models\WhitelistDomain;
use App\Models\Notification;
use App\Models\SubscriptionPlan;
use App\Services\SecurityScoreService;
use App\Services\Security\ReportService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class DashboardController extends Controller
{
    /**
     * Dashboard Command Center Overview
     */
    public function index(SecurityScoreService $scoreService)
    {
        $user = Auth::user();
        $recentScans = ScanHistory::where('user_id', $user->id)->orderBy('created_at', 'desc')->take(6)->get();
        $totalScans = ScanHistory::where('user_id', $user->id)->count();
        $threatsBlocked = ScanHistory::where('user_id', $user->id)->where('risk_level', 'high')->count();
        $safeScans = ScanHistory::where('user_id', $user->id)->where('risk_level', 'safe')->count();

        // Calculate real-time personal security score
        $securityScoreData = $scoreService->calculate($user);

        // Fetch unread notifications count
        $unreadNotificationsCount = Notification::where('user_id', $user->id)->where('is_read', false)->count();

        return view('dashboard', [
            'user' => $user,
            'recentScans' => $recentScans,
            'totalScans' => $totalScans,
            'threatsBlocked' => $threatsBlocked,
            'safeScans' => $safeScans,
            'securityScore' => $securityScoreData,
            'unreadNotificationsCount' => $unreadNotificationsCount,
        ]);
    }

    /**
     * Scan History Log
     */
    public function history(Request $request)
    {
        $user = Auth::user();
        $query = ScanHistory::where('user_id', $user->id);

        if ($request->filled('search')) {
            $search = trim($request->search);
            $query->where('content', 'LIKE', "%{$search}%");
        }

        if ($request->filled('risk')) {
            $risk = strtolower(trim($request->risk));
            if (in_array($risk, ['safe', 'medium', 'high', 'critical'])) {
                $query->where('risk_level', $risk);
            }
        }

        $scans = $query->orderBy('created_at', 'desc')->paginate(15)->withQueryString();

        return view('history', [
            'scans' => $scans,
            'currentSearch' => $request->search,
            'currentRisk' => $request->risk,
        ]);
    }

    /**
     * Reports Archive & Management
     */
    public function reports(Request $request)
    {
        $user = Auth::user();
        $query = ScanHistory::where('user_id', $user->id);

        if ($request->filled('q')) {
            $q = trim($request->q);
            $query->where('content', 'LIKE', "%{$q}%");
        }

        if ($request->filled('level')) {
            $level = strtolower(trim($request->level));
            if ($level !== 'all') {
                $query->where('risk_level', $level);
            }
        }

        $reports = $query->orderBy('created_at', 'desc')->paginate(12)->withQueryString();
        $totalReports = ScanHistory::where('user_id', $user->id)->count();
        $highRiskReports = ScanHistory::where('user_id', $user->id)->where('risk_level', 'high')->count();

        return view('reports', [
            'reports' => $reports,
            'totalReports' => $totalReports,
            'highRiskReports' => $highRiskReports,
            'querySearch' => $request->q,
            'queryLevel' => $request->level ?? 'all',
        ]);
    }

    /**
     * Complete Full Security Report Details Page
     */
    public function reportDetail($id, ReportService $reportService)
    {
        $user = Auth::user();
        $scan = ScanHistory::where('id', $id)
            ->where(function ($q) use ($user) {
                $q->where('user_id', $user->id)->orWhereNull('user_id');
            })
            ->firstOrFail();

        $reportData = $reportService->generateReportData($scan);

        return view('report_detail', [
            'report' => $reportData,
            'scan' => $scan,
        ]);
    }

    /**
     * Personal Security Score Interactive Center
     */
    public function securityScore(SecurityScoreService $scoreService)
    {
        $user = Auth::user();
        $scoreData = $scoreService->calculate($user);

        return view('security_score', [
            'scoreData' => $scoreData,
            'user' => $user,
        ]);
    }

    /**
     * Notifications & Threat Alerts Center
     */
    public function notifications(Request $request)
    {
        $user = Auth::user();

        // Seed initial notifications if none exist
        if (Notification::where('user_id', $user->id)->count() === 0) {
            Notification::create([
                'user_id' => $user->id,
                'title' => 'Real-Time Protection Activated',
                'message' => 'Block Bord AI heuristic shield is monitoring all active URL and scam requests.',
                'type' => 'info',
                'is_read' => false,
            ]);
            Notification::create([
                'user_id' => $user->id,
                'title' => 'Security Recommendation: Enable 2FA',
                'message' => 'Add two-factor authentication in Account Settings to boost your Security Score to A+.',
                'type' => 'warning',
                'is_read' => false,
            ]);
        }

        $query = Notification::where('user_id', $user->id);

        if ($request->filled('type') && $request->type !== 'all') {
            $query->where('type', $request->type);
        }

        $notifications = $query->orderBy('created_at', 'desc')->paginate(15)->withQueryString();
        $unreadCount = Notification::where('user_id', $user->id)->where('is_read', false)->count();

        return view('notifications', [
            'notifications' => $notifications,
            'unreadCount' => $unreadCount,
            'currentType' => $request->type ?? 'all',
        ]);
    }

    /**
     * Mark single notification as read
     */
    public function markNotificationRead($id)
    {
        $user = Auth::user();
        Notification::where('user_id', $user->id)->where('id', $id)->update(['is_read' => true]);

        if (request()->wantsJson()) {
            return response()->json(['success' => true]);
        }

        return back()->with('success', 'Notification marked as read.');
    }

    /**
     * Mark all notifications as read
     */
    public function markAllNotificationsRead()
    {
        $user = Auth::user();
        Notification::where('user_id', $user->id)->update(['is_read' => true]);

        if (request()->wantsJson()) {
            return response()->json(['success' => true]);
        }

        return back()->with('success', 'All notifications marked as read.');
    }

    /**
     * Delete notification
     */
    public function deleteNotification($id)
    {
        $user = Auth::user();
        Notification::where('user_id', $user->id)->where('id', $id)->delete();

        if (request()->wantsJson()) {
            return response()->json(['success' => true]);
        }

        return back()->with('success', 'Notification dismissed.');
    }

    /**
     * Subscription & Plans Management
     */
    public function subscription()
    {
        $user = Auth::user();
        $plans = SubscriptionPlan::all();

        return view('subscription', [
            'user' => $user,
            'plans' => $plans,
        ]);
    }

    /**
     * Threat Analytics
     */
    public function analytics()
    {
        $user = Auth::user();
        $totalScans = ScanHistory::where('user_id', $user->id)->count();
        $safeCount = ScanHistory::where('user_id', $user->id)->where('risk_level', 'safe')->count();
        $mediumCount = ScanHistory::where('user_id', $user->id)->where('risk_level', 'medium')->count();
        $highCount = ScanHistory::where('user_id', $user->id)->where('risk_level', 'high')->count();

        return view('analytics', [
            'totalScans' => $totalScans,
            'safeCount' => $safeCount,
            'mediumCount' => $mediumCount,
            'highCount' => $highCount,
        ]);
    }

    /**
     * Account & Security Settings
     */
    public function settings()
    {
        return view('settings', ['user' => Auth::user()]);
    }

    /**
     * Update Account Settings
     */
    public function updateSettings(Request $request)
    {
        $user = Auth::user();

        $request->validate([
            'username' => 'required|string|max:191|unique:users,username,' . $user->id,
            'email' => 'required|email|max:191|unique:users,email,' . $user->id,
            'current_password' => 'nullable|string',
            'new_password' => 'nullable|string|min:12',
        ]);

        $user->username = trim($request->username);
        $user->email = strtolower(trim($request->email));

        if ($request->filled('new_password')) {
            if (!$request->filled('current_password') || !Hash::check($request->current_password, $user->password)) {
                return back()->with('error', 'Current password is incorrect.');
            }
            $user->password = Hash::make($request->new_password);
        }

        $user->save();

        return back()->with('success', 'Account settings updated successfully.');
    }

    /**
     * Extension Setup Page
     */
    public function extensionSetup()
    {
        return view('extension_setup');
    }

    /**
     * Custom Block / Allow List
     */
    public function blockList()
    {
        $user = Auth::user();
        $blacklists = BlacklistDomain::where('added_by_user_id', $user->id)->get();
        $whitelists = WhitelistDomain::where('added_by_user_id', $user->id)->get();

        return view('block_list', [
            'blacklists' => $blacklists,
            'whitelists' => $whitelists,
        ]);
    }
}
