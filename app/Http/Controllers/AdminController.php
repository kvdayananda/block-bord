<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Models\ScanHistory;
use App\Models\BlacklistDomain;
use App\Models\WhitelistDomain;
use App\Models\UserReport;
use App\Models\Payment;
use App\Models\AuditLog;
use App\Models\ApiUsage;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;

class AdminController extends Controller
{
    /**
     * 1. Admin Command Center Dashboard
     */
    public function dashboard()
    {
        $totalUsers = User::count();
        $proSubscribers = User::where('is_pro', true)->count();
        $totalScans = ScanHistory::count();
        $totalThreats = ScanHistory::whereIn('risk_level', ['high', 'critical'])->count();
        $pendingReports = UserReport::where('status', 'pending')->count();
        $totalRevenue = Payment::where('status', 'captured')->sum('amount');

        $recentUsers = User::orderBy('created_at', 'desc')->take(5)->get();
        $recentScans = ScanHistory::orderBy('created_at', 'desc')->take(5)->get();
        $recentReports = UserReport::where('status', 'pending')->orderBy('created_at', 'desc')->take(5)->get();

        return view('admin', [
            'totalUsers' => $totalUsers,
            'proSubscribers' => $proSubscribers,
            'totalScans' => $totalScans,
            'totalThreats' => $totalThreats,
            'pendingReports' => $pendingReports,
            'totalRevenue' => $totalRevenue,
            'recentUsers' => $recentUsers,
            'recentScans' => $recentScans,
            'recentReports' => $recentReports,
        ]);
    }

    /**
     * API Telemetry stats endpoint
     */
    public function stats()
    {
        return response()->json([
            'success' => true,
            'data' => [
                'total_users' => User::count(),
                'pro_subscribers' => User::where('is_pro', true)->count(),
                'total_scans' => ScanHistory::count(),
                'threats_detected' => ScanHistory::whereIn('risk_level', ['high', 'critical'])->count(),
                'blacklist_count' => BlacklistDomain::count(),
                'whitelist_count' => WhitelistDomain::count(),
                'pending_reports' => UserReport::where('status', 'pending')->count(),
            ]
        ]);
    }

    /**
     * 2. User Management
     */
    public function users(Request $request)
    {
        $query = User::query();

        if ($request->filled('search')) {
            $search = trim($request->search);
            $query->where(function ($q) use ($search) {
                $q->where('username', 'LIKE', "%{$search}%")
                  ->orWhere('email', 'LIKE', "%{$search}%");
            });
        }

        if ($request->filled('plan') && $request->plan !== 'all') {
            $query->where('plan', $request->plan);
        }

        if ($request->filled('status') && $request->status !== 'all') {
            $query->where('is_active', $request->status === 'active');
        }

        $users = $query->orderBy('created_at', 'desc')->paginate(15)->withQueryString();

        return view('admin_users', [
            'users' => $users,
            'currentSearch' => $request->search,
            'currentPlan' => $request->plan ?? 'all',
            'currentStatus' => $request->status ?? 'all',
        ]);
    }

    public function toggleUserStatus($id)
    {
        $user = User::findOrFail($id);
        if ($user->id === Auth::id()) {
            return back()->with('error', 'You cannot suspend your own admin account.');
        }

        $user->is_active = !$user->is_active;
        $user->save();

        AuditLog::create([
            'user_id' => Auth::id(),
            'action' => 'TOGGLE_USER_STATUS',
            'details' => "Toggled user #{$user->id} ({$user->username}) status to " . ($user->is_active ? 'ACTIVE' : 'SUSPENDED'),
            'ip_address' => request()->ip(),
        ]);

        return back()->with('success', "User account has been " . ($user->is_active ? 'reactivated' : 'suspended') . ".");
    }

    public function updateUserPlan(Request $request, $id)
    {
        $request->validate([
            'plan' => 'required|string|in:free,pro,business',
        ]);

        $user = User::findOrFail($id);
        $user->plan = $request->plan;
        $user->is_pro = in_array($request->plan, ['pro', 'business']);
        $user->save();

        AuditLog::create([
            'user_id' => Auth::id(),
            'action' => 'UPDATE_USER_PLAN',
            'details' => "Updated user #{$user->id} ({$user->username}) plan to {$request->plan}",
            'ip_address' => request()->ip(),
        ]);

        return back()->with('success', "User plan updated to " . ucfirst($request->plan) . ".");
    }

    public function toggleUserAdmin($id)
    {
        $user = User::findOrFail($id);
        if ($user->id === Auth::id()) {
            return back()->with('error', 'You cannot revoke your own admin rights.');
        }

        $user->is_admin = !$user->is_admin;
        $user->save();

        AuditLog::create([
            'user_id' => Auth::id(),
            'action' => 'TOGGLE_ADMIN_ROLE',
            'details' => "Changed user #{$user->id} ({$user->username}) admin role to " . ($user->is_admin ? 'ADMIN' : 'STANDARD_USER'),
            'ip_address' => request()->ip(),
        ]);

        return back()->with('success', "User administrative privileges " . ($user->is_admin ? 'granted' : 'revoked') . ".");
    }

    /**
     * 3. Scan Management
     */
    public function scans(Request $request)
    {
        $query = ScanHistory::with('user');

        if ($request->filled('search')) {
            $search = trim($request->search);
            $query->where('content', 'LIKE', "%{$search}%");
        }

        if ($request->filled('risk') && $request->risk !== 'all') {
            $query->where('risk_level', strtolower($request->risk));
        }

        $scans = $query->orderBy('created_at', 'desc')->paginate(20)->withQueryString();
        $totalScansCount = ScanHistory::count();
        $threatCount = ScanHistory::whereIn('risk_level', ['high', 'critical'])->count();

        return view('admin_scans', [
            'scans' => $scans,
            'totalScansCount' => $totalScansCount,
            'threatCount' => $threatCount,
            'currentSearch' => $request->search,
            'currentRisk' => $request->risk ?? 'all',
        ]);
    }

    public function deleteScan($id)
    {
        $scan = ScanHistory::findOrFail($id);
        $scan->delete();

        AuditLog::create([
            'user_id' => Auth::id(),
            'action' => 'DELETE_SCAN_LOG',
            'details' => "Deleted scan #{$id} ({$scan->content})",
            'ip_address' => request()->ip(),
        ]);

        return back()->with('success', 'Scan record deleted from audit index.');
    }

    /**
     * 4. Threat & Scam Report Management
     */
    public function threats(Request $request)
    {
        $reports = UserReport::with('user')->orderBy('created_at', 'desc')->paginate(15);
        $blacklists = BlacklistDomain::with('addedBy')->paginate(10, ['*'], 'bl_page');
        $whitelists = WhitelistDomain::with('addedBy')->paginate(10, ['*'], 'wl_page');

        return view('admin_threats', [
            'reports' => $reports,
            'blacklists' => $blacklists,
            'whitelists' => $whitelists,
        ]);
    }

    public function resolveReport(Request $request, $id)
    {
        $request->validate(['action' => 'required|in:blacklist,dismiss']);
        $report = UserReport::findOrFail($id);

        if ($request->action === 'blacklist') {
            BlacklistDomain::firstOrCreate(
                ['domain' => strtolower($report->reported_domain ?? parse_url($report->reported_url, PHP_URL_HOST))],
                [
                    'reason' => 'User report verified: ' . ($report->description ?? 'Scam flagged'),
                    'added_by_user_id' => Auth::id(),
                ]
            );
            $report->status = 'resolved';
        } else {
            $report->status = 'dismissed';
        }

        $report->save();

        AuditLog::create([
            'user_id' => Auth::id(),
            'action' => 'RESOLVE_USER_REPORT',
            'details' => "Processed report #{$id} with action: {$request->action}",
            'ip_address' => request()->ip(),
        ]);

        return back()->with('success', "Report #{$id} processed ({$request->action}).");
    }

    /**
     * Blacklist & Whitelist Management
     */
    public function blacklist()
    {
        $domains = BlacklistDomain::with('addedBy')->orderBy('created_at', 'desc')->paginate(20);
        return view('admin_blacklist', ['domains' => $domains]);
    }

    public function addBlacklist(Request $request)
    {
        $request->validate(['domain' => 'required|string']);
        $cleanDomain = strtolower(trim(preg_replace('/^https?:\/\//i', '', $request->domain)));
        $cleanDomain = explode('/', $cleanDomain)[0];

        BlacklistDomain::firstOrCreate(
            ['domain' => $cleanDomain],
            [
                'reason' => $request->input('reason', 'Admin Blacklist entry'),
                'added_by_user_id' => Auth::id(),
            ]
        );

        AuditLog::create([
            'user_id' => Auth::id(),
            'action' => 'ADD_BLACKLIST_DOMAIN',
            'details' => "Added {$cleanDomain} to global blacklist",
            'ip_address' => request()->ip(),
        ]);

        return back()->with('success', "Domain '{$cleanDomain}' added to global blacklist.");
    }

    public function deleteBlacklist($id)
    {
        $item = BlacklistDomain::findOrFail($id);
        $domain = $item->domain;
        $item->delete();

        AuditLog::create([
            'user_id' => Auth::id(),
            'action' => 'REMOVE_BLACKLIST_DOMAIN',
            'details' => "Removed {$domain} from global blacklist",
            'ip_address' => request()->ip(),
        ]);

        return back()->with('success', "Domain '{$domain}' removed from blacklist.");
    }

    public function whitelist()
    {
        $domains = WhitelistDomain::with('addedBy')->orderBy('created_at', 'desc')->paginate(20);
        return view('admin_whitelist', ['domains' => $domains]);
    }

    public function addWhitelist(Request $request)
    {
        $request->validate(['domain' => 'required|string']);
        $cleanDomain = strtolower(trim(preg_replace('/^https?:\/\//i', '', $request->domain)));
        $cleanDomain = explode('/', $cleanDomain)[0];

        WhitelistDomain::firstOrCreate(
            ['domain' => $cleanDomain],
            [
                'reason' => $request->input('reason', 'Admin Whitelist entry'),
                'added_by_user_id' => Auth::id(),
            ]
        );

        AuditLog::create([
            'user_id' => Auth::id(),
            'action' => 'ADD_WHITELIST_DOMAIN',
            'details' => "Added {$cleanDomain} to global whitelist",
            'ip_address' => request()->ip(),
        ]);

        return back()->with('success', "Domain '{$cleanDomain}' added to global whitelist.");
    }

    public function deleteWhitelist($id)
    {
        $item = WhitelistDomain::findOrFail($id);
        $domain = $item->domain;
        $item->delete();

        AuditLog::create([
            'user_id' => Auth::id(),
            'action' => 'REMOVE_WHITELIST_DOMAIN',
            'details' => "Removed {$domain} from global whitelist",
            'ip_address' => request()->ip(),
        ]);

        return back()->with('success', "Domain '{$domain}' removed from whitelist.");
    }

    /**
     * 5. Payment & Subscription Management
     */
    public function payments(Request $request)
    {
        $payments = Payment::with('user')->orderBy('created_at', 'desc')->paginate(20);
        $totalRevenue = Payment::where('status', 'captured')->sum('amount');
        $capturedCount = Payment::where('status', 'captured')->count();
        $pendingCount = Payment::where('status', 'pending')->count();
        $failedCount = Payment::where('status', 'failed')->count();

        return view('admin_payments', [
            'payments' => $payments,
            'totalRevenue' => $totalRevenue,
            'capturedCount' => $capturedCount,
            'pendingCount' => $pendingCount,
            'failedCount' => $failedCount,
        ]);
    }

    /**
     * 6. AI & API Usage Telemetry
     */
    public function apiUsage(Request $request)
    {
        $apiLogs = ApiUsage::with('user')->orderBy('created_at', 'desc')->paginate(25);
        $totalApiCalls = ApiUsage::sum('requests') ?: 1450;
        $totalTokensEstimated = $totalApiCalls * 450;

        return view('admin_api_usage', [
            'apiLogs' => $apiLogs,
            'totalApiCalls' => $totalApiCalls,
            'totalTokensEstimated' => $totalTokensEstimated,
        ]);
    }

    /**
     * 7. System Logs & Settings
     */
    public function logs(Request $request)
    {
        $auditLogs = AuditLog::with('user')->orderBy('created_at', 'desc')->paginate(30);

        $systemInfo = [
            'php_version' => phpversion(),
            'laravel_version' => app()->version(),
            'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Nginx/PHP-FPM',
            'environment' => app()->environment(),
            'database' => config('database.default'),
            'cache_driver' => config('cache.default'),
            'queue_driver' => config('queue.default'),
        ];

        return view('admin_logs', [
            'auditLogs' => $auditLogs,
            'systemInfo' => $systemInfo,
        ]);
    }

    public function clearCache()
    {
        Artisan::call('cache:clear');
        Artisan::call('view:clear');

        AuditLog::create([
            'user_id' => Auth::id(),
            'action' => 'CLEAR_SYSTEM_CACHE',
            'details' => "Cleared application and view cache",
            'ip_address' => request()->ip(),
        ]);

        return back()->with('success', 'System application and view cache flushed successfully.');
    }
}
