<?php

namespace App\Http\Controllers;

use App\Models\ScanHistory;
use App\Models\BlacklistDomain;
use App\Models\WhitelistDomain;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class DashboardController extends Controller
{
    public function index()
    {
        $user = Auth::user();
        $recentScans = ScanHistory::where('user_id', $user->id)->orderBy('created_at', 'desc')->take(5)->get();
        $totalScans = ScanHistory::where('user_id', $user->id)->count();
        $threatsBlocked = ScanHistory::where('user_id', $user->id)->where('risk_level', 'high')->count();

        return view('dashboard', [
            'user' => $user,
            'recentScans' => $recentScans,
            'totalScans' => $totalScans,
            'threatsBlocked' => $threatsBlocked,
        ]);
    }

    public function history()
    {
        $user = Auth::user();
        $scans = ScanHistory::where('user_id', $user->id)->orderBy('created_at', 'desc')->paginate(15);
        return view('history', ['scans' => $scans]);
    }

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

    public function settings()
    {
        return view('settings', ['user' => Auth::user()]);
    }

    public function extensionSetup()
    {
        return view('extension_setup');
    }

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
