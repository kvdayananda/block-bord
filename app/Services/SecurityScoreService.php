<?php

namespace App\Services;

use App\Models\User;
use App\Models\ScanHistory;
use App\Models\BlacklistDomain;
use App\Models\WhitelistDomain;
use App\Models\SecurityScore;

class SecurityScoreService
{
    /**
     * Calculate and persist the comprehensive Personal Security Score for a user.
     */
    public function calculate(User $user): array
    {
        $score = 0;
        $factors = [];

        // 1. Two-Factor Authentication (Weight: 25)
        if ($user->totp_enabled) {
            $score += 25;
            $factors[] = [
                'id' => '2fa',
                'title' => 'Two-Factor Authentication (2FA)',
                'points' => 25,
                'max_points' => 25,
                'status' => 'passed',
                'description' => '2FA is active, protecting your account against credential theft.',
                'action_label' => 'Manage 2FA',
                'action_route' => route('settings'),
            ];
        } else {
            $score += 0;
            $factors[] = [
                'id' => '2fa',
                'title' => 'Two-Factor Authentication (2FA)',
                'points' => 0,
                'max_points' => 25,
                'status' => 'warning',
                'description' => 'Two-factor authentication is disabled. Your account is susceptible to password spray and brute-force attacks.',
                'action_label' => 'Enable 2FA',
                'action_route' => route('settings'),
            ];
        }

        // 2. Email Verification & Security Alerts (Weight: 15)
        if ($user->is_email_verified) {
            $score += 15;
            $factors[] = [
                'id' => 'email_verification',
                'title' => 'Email Identity Verification',
                'points' => 15,
                'max_points' => 15,
                'status' => 'passed',
                'description' => 'Your email address is verified for real-time security alerts and breach notifications.',
                'action_label' => 'Verified',
                'action_route' => route('settings'),
            ];
        } else {
            $score += 5;
            $factors[] = [
                'id' => 'email_verification',
                'title' => 'Email Identity Verification',
                'points' => 5,
                'max_points' => 15,
                'status' => 'warning',
                'description' => 'Email is unverified. Threat alerts cannot be dispatched safely.',
                'action_label' => 'Verify Email',
                'action_route' => route('verification.notice'),
            ];
        }

        // 3. Active Browser Shield / API Key (Weight: 20)
        if (!empty($user->api_key)) {
            $score += 20;
            $factors[] = [
                'id' => 'api_shield',
                'title' => 'API Shield & Extension Integration',
                'points' => 20,
                'max_points' => 20,
                'status' => 'passed',
                'description' => 'Active API Key provisioned for automated extension and CLI scanning.',
                'action_label' => 'View Extension Setup',
                'action_route' => route('extension.setup'),
            ];
        } else {
            $score += 5;
            $factors[] = [
                'id' => 'api_shield',
                'title' => 'API Shield & Extension Integration',
                'points' => 5,
                'max_points' => 20,
                'status' => 'warning',
                'description' => 'No API Key generated. Browser extension cannot sync real-time protection telemetry.',
                'action_label' => 'Generate API Key',
                'action_route' => route('settings'),
            ];
        }

        // 4. Custom Perimeter Controls / Blocklist (Weight: 20)
        $rulesCount = BlacklistDomain::where('added_by_user_id', $user->id)->count() +
                      WhitelistDomain::where('added_by_user_id', $user->id)->count();
        if ($rulesCount > 0) {
            $score += 20;
            $factors[] = [
                'id' => 'perimeter_rules',
                'title' => 'Custom Perimeter Domain Rules',
                'points' => 20,
                'max_points' => 20,
                'status' => 'passed',
                'description' => "You have {$rulesCount} active custom domain rules governing your network shield.",
                'action_label' => 'Manage Rules',
                'action_route' => route('block_list'),
            ];
        } else {
            $score += 10;
            $factors[] = [
                'id' => 'perimeter_rules',
                'title' => 'Custom Perimeter Domain Rules',
                'points' => 10,
                'max_points' => 20,
                'status' => 'info',
                'description' => 'Using global threat intelligence. Add custom domains to your block/allow lists for personalized perimeter defense.',
                'action_label' => 'Add Domain Rules',
                'action_route' => route('block_list'),
            ];
        }

        // 5. Threat Exposure & Inspection History (Weight: 20)
        $scans = ScanHistory::where('user_id', $user->id)->get();
        $totalScans = $scans->count();
        $threatScans = $scans->where('risk_level', 'high')->count();

        if ($totalScans > 0) {
            if ($threatScans === 0) {
                $score += 20;
                $factors[] = [
                    'id' => 'threat_exposure',
                    'title' => 'Threat Interception Baseline',
                    'points' => 20,
                    'max_points' => 20,
                    'status' => 'passed',
                    'description' => "Analyzed {$totalScans} targets with 0 high-risk security compromises.",
                    'action_label' => 'View History',
                    'action_route' => route('history'),
                ];
            } else {
                $points = max(5, 20 - ($threatScans * 3));
                $score += $points;
                $factors[] = [
                    'id' => 'threat_exposure',
                    'title' => 'Threat Interception Baseline',
                    'points' => $points,
                    'max_points' => 20,
                    'status' => 'alert',
                    'description' => "Intercepted {$threatScans} malicious/high-risk targets across {$totalScans} total inspections.",
                    'action_label' => 'Review Threats',
                    'action_route' => route('history'),
                ];
            }
        } else {
            $score += 15;
            $factors[] = [
                'id' => 'threat_exposure',
                'title' => 'Threat Interception Baseline',
                'points' => 15,
                'max_points' => 20,
                'status' => 'info',
                'description' => 'No URL or scam inspections recorded yet. Run your first inspection to calibrate threat baseline.',
                'action_label' => 'Run Security Scan',
                'action_route' => route('tools.home'),
            ];
        }

        // Clamp score between 0 and 100
        $score = min(100, max(0, $score));

        // Rating & Grade computation
        if ($score >= 90) {
            $grade = 'A+';
            $rating = 'Optimal Security Shield';
            $color = '#10b981';
        } elseif ($score >= 80) {
            $grade = 'A';
            $rating = 'Strong Protection';
            $color = '#22c55e';
        } elseif ($score >= 65) {
            $grade = 'B';
            $rating = 'Moderate Defense';
            $color = '#f59e0b';
        } elseif ($score >= 45) {
            $grade = 'C';
            $rating = 'Vulnerabilities Detected';
            $color = '#f97316';
        } else {
            $grade = 'D';
            $rating = 'Critical Action Required';
            $color = '#ef4444';
        }

        // Persist to database
        SecurityScore::updateOrCreate(
            ['user_id' => $user->id],
            [
                'score' => $score,
                'factors' => $factors,
            ]
        );

        return [
            'score' => $score,
            'grade' => $grade,
            'rating' => $rating,
            'color' => $color,
            'factors' => $factors,
            'total_scans' => $totalScans,
            'threats_blocked' => $threatScans,
            'user' => $user,
        ];
    }
}
