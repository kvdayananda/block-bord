<?php

namespace App\Http\Controllers;

use App\Models\User;
use App\Models\ScanHistory;
use App\Models\BlacklistDomain;
use App\Models\WhitelistDomain;
use App\Models\UserReport;
use Illuminate\Http\Request;

class AdminController extends Controller
{
    public function dashboard()
    {
        $totalUsers = User::count();
        $totalScans = ScanHistory::count();
        $totalThreats = ScanHistory::where('risk_level', 'high')->count();
        $pendingReports = UserReport::where('status', 'pending')->count();

        return view('admin', [
            'totalUsers' => $totalUsers,
            'totalScans' => $totalScans,
            'totalThreats' => $totalThreats,
            'pendingReports' => $pendingReports,
        ]);
    }

    public function stats()
    {
        return response()->json([
            'success' => true,
            'data' => [
                'total_users' => User::count(),
                'total_scans' => ScanHistory::count(),
                'threats_detected' => ScanHistory::where('risk_level', 'high')->count(),
                'pro_subscribers' => User::where('is_pro', true)->count(),
            ]
        ]);
    }

    public function users()
    {
        $users = User::paginate(20);
        return view('admin_users', ['users' => $users]);
    }

    public function blacklist()
    {
        $domains = BlacklistDomain::with('addedBy')->paginate(20);
        return view('admin_blacklist', ['domains' => $domains]);
    }

    public function addBlacklist(Request $request)
    {
        $request->validate(['domain' => 'required|string']);
        BlacklistDomain::firstOrCreate(
            ['domain' => strtolower(trim($request->domain))],
            ['reason' => $request->input('reason', 'Admin Blacklist')]
        );

        return back()->with('success', 'Domain added to blacklist successfully.');
    }

    public function whitelist()
    {
        $domains = WhitelistDomain::with('addedBy')->paginate(20);
        return view('admin_whitelist', ['domains' => $domains]);
    }

    public function addWhitelist(Request $request)
    {
        $request->validate(['domain' => 'required|string']);
        WhitelistDomain::firstOrCreate(
            ['domain' => strtolower(trim($request->domain))],
            ['reason' => $request->input('reason', 'Admin Whitelist')]
        );

        return back()->with('success', 'Domain added to whitelist successfully.');
    }
}
