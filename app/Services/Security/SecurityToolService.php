<?php

namespace App\Services\Security;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;

class SecurityToolService
{
    protected GoogleSafeBrowsingService $gsbService;

    public function __construct(GoogleSafeBrowsingService $gsbService)
    {
        $this->gsbService = $gsbService;
    }

    public function scanUrl(string $url): array
    {
        $domain = parse_url($url, PHP_URL_HOST) ?? $url;
        $urlHash = hash('sha256', strtolower($url));
        
        $suspiciousKeywords = ['login', 'verify', 'update', 'banking', 'secure', 'account', 'signin', 'free', 'bonus', 'wallet', 'claim', 'gift'];
        $foundKeywords = [];
        foreach ($suspiciousKeywords as $kw) {
            if (stripos($url, $kw) !== false) {
                $foundKeywords[] = "Contains suspicious keyword: {$kw}";
            }
        }

        $riskScore = count($foundKeywords) * 20.0;
        if (strlen($url) > 75) {
            $riskScore += 15;
            $foundKeywords[] = "Unusually long URL length (>75 characters)";
        }
        if (substr_count($url, '.') > 4) {
            $riskScore += 15;
            $foundKeywords[] = "Excessive subdomain levels";
        }
        if (preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/', $domain)) {
            $riskScore += 25;
            $foundKeywords[] = "Raw IP address used as hostname";
        }

        // Google Safe Browsing Check
        $gsbResult = $this->gsbService->checkUrl($url);
        if ($gsbResult['is_malicious']) {
            $riskScore = 100.0;
            foreach ($gsbResult['threat_types'] as $threat) {
                $foundKeywords[] = "Google Safe Browsing Flag: {$threat}";
            }
        }

        $riskScore = min(100.0, max(0.0, $riskScore));
        $riskLevel = $riskScore >= 70 ? 'high' : ($riskScore >= 35 ? 'medium' : 'safe');

        return [
            'url' => $url,
            'domain' => $domain,
            'url_hash' => $urlHash,
            'risk_score' => $riskScore,
            'risk_level' => $riskLevel,
            'reasons' => $foundKeywords,
            'scam_intent' => $riskScore >= 70 ? 'Credential Harvesting / Phishing' : 'Informational',
            'gsb_status' => $gsbResult['status'],
            'scanned_at' => now()->toIso8601String(),
        ];
    }

    public function lookupDomain(string $domain): array
    {
        $cleanDomain = preg_replace('/^https?:\/\//', '', trim($domain));
        $cleanDomain = explode('/', $cleanDomain)[0];
        $ip = gethostbyname($cleanDomain);
        $dnsRecords = @dns_get_record($cleanDomain, DNS_A + DNS_MX + DNS_NS + DNS_TXT) ?: [];

        return [
            'domain' => $cleanDomain,
            'ip_address' => $ip !== $cleanDomain ? $ip : 'Unresolved',
            'dns_records' => $dnsRecords,
            'status' => $ip !== $cleanDomain ? 'active' : 'unreachable',
            'checked_at' => now()->toIso8601String(),
        ];
    }

    public function lookupIp(string $ip): array
    {
        try {
            $res = Http::timeout(4)->get("http://ip-api.com/json/{$ip}");
            if ($res->successful()) {
                $data = $res->json();
                return [
                    'ip' => $ip,
                    'country' => $data['country'] ?? 'Unknown',
                    'city' => $data['city'] ?? 'Unknown',
                    'isp' => $data['isp'] ?? 'Unknown',
                    'org' => $data['org'] ?? 'Unknown',
                    'is_proxy' => false,
                ];
            }
        } catch (\Exception $e) {
            // Fallback
        }

        return [
            'ip' => $ip,
            'country' => 'Local / Reserved',
            'city' => 'Local',
            'isp' => 'Internal / Private',
            'org' => 'Internal',
            'is_proxy' => false,
        ];
    }

    public function checkEmailHeader(string $headerText): array
    {
        $spfFound = stripos($headerText, 'spf=pass') !== false || stripos($headerText, 'received-spf: pass') !== false;
        $dkimFound = stripos($headerText, 'dkim=pass') !== false || stripos($headerText, 'dkim-signature:') !== false;
        $dmarcFound = stripos($headerText, 'dmarc=pass') !== false || stripos($headerText, 'header.from=') !== false;

        $riskScore = 0;
        if (!$spfFound) $riskScore += 35;
        if (!$dkimFound) $riskScore += 35;
        if (!$dmarcFound) $riskScore += 30;

        return [
            'spf_pass' => $spfFound,
            'dkim_pass' => $dkimFound,
            'dmarc_pass' => $dmarcFound,
            'risk_score' => $riskScore,
            'authenticity' => $riskScore === 0 ? 'High' : ($riskScore < 60 ? 'Medium' : 'Low / Phishing Suspect'),
        ];
    }

    public function checkPassword(string $password): array
    {
        $hash = strtoupper(sha1($password));
        $prefix = substr($hash, 0, 5);
        $suffix = substr($hash, 5);

        $breachCount = 0;
        try {
            $res = Http::timeout(4)->get("https://api.pwnedpasswords.com/range/{$prefix}");
            if ($res->successful()) {
                $lines = explode("\n", $res->body());
                foreach ($lines as $line) {
                    $parts = explode(':', trim($line));
                    if (count($parts) === 2 && $parts[0] === $suffix) {
                        $breachCount = (int)$parts[1];
                        break;
                    }
                }
            }
        } catch (\Exception $e) {
            // Fallback rating
        }

        return [
            'is_pwned' => $breachCount > 0,
            'breach_count' => $breachCount,
            'strength_rating' => $breachCount === 0 ? 'Strong' : 'Compromised',
        ];
    }

    public function checkSsl(string $domain): array
    {
        $cleanDomain = preg_replace('/^https?:\/\//', '', trim($domain));
        $cleanDomain = explode('/', $cleanDomain)[0];

        $gcontext = stream_context_create([
            "ssl" => [
                "capture_peer_cert" => true,
                "verify_peer" => false,
                "verify_peer_name" => false
            ]
        ]);

        $client = @stream_socket_client(
            "ssl://{$cleanDomain}:443",
            $errno,
            $errstr,
            5,
            STREAM_CLIENT_CONNECT,
            $gcontext
        );

        if ($client) {
            $params = stream_context_get_params($client);
            fclose($client);

            if (isset($params["options"]["ssl"]["peer_certificate"])) {
                $cert = openssl_x509_parse($params["options"]["ssl"]["peer_certificate"]);
                $validTo = $cert['validTo_time_t'] ?? time();
                $daysRemaining = (int)ceil(($validTo - time()) / 86400);

                return [
                    'domain' => $cleanDomain,
                    'valid' => $daysRemaining > 0,
                    'issuer' => $cert['issuer']['O'] ?? ($cert['issuer']['CN'] ?? 'Unknown Issuer'),
                    'subject' => $cert['subject']['CN'] ?? $cleanDomain,
                    'valid_from' => date('Y-m-d', $cert['validFrom_time_t'] ?? time()),
                    'valid_to' => date('Y-m-d', $validTo),
                    'days_remaining' => max(0, $daysRemaining),
                    'checked_at' => now()->toIso8601String(),
                ];
            }
        }

        return [
            'domain' => $cleanDomain,
            'valid' => false,
            'issuer' => 'Connection Failed / No SSL',
            'subject' => $cleanDomain,
            'valid_from' => null,
            'valid_to' => null,
            'days_remaining' => 0,
            'checked_at' => now()->toIso8601String(),
        ];
    }

    public function checkUpiScam(string $vpaOrPhone): array
    {
        $input = trim($vpaOrPhone);
        $isVpa = strpos($input, '@') !== false;

        $suspiciousHandles = ['cashback', 'reward', 'refund', 'lottery', 'kyc', 'support', 'helpdesk'];
        $isSuspicious = false;

        foreach ($suspiciousHandles as $handle) {
            if (stripos($input, $handle) !== false) {
                $isSuspicious = true;
                break;
            }
        }

        return [
            'query' => $input,
            'type' => $isVpa ? 'vpa' : 'phone_number',
            'risk_level' => $isSuspicious ? 'high' : 'safe',
            'recommendation' => $isSuspicious ? 'Do NOT send money to unverified handles requesting cashbacks or rewards.' : 'Always verify recipient name on your UPI app before entering PIN.',
            'checked_at' => now()->toIso8601String(),
        ];
    }

    public function checkHeaders(string $url): array
    {
        $domain = parse_url($url, PHP_URL_HOST) ?? $url;
        $target = "https://" . preg_replace('/^https?:\/\//', '', trim($domain));

        try {
            $response = Http::timeout(5)->get($target);
            $headers = $response->headers();

            $securityHeaders = [
                'Strict-Transport-Security' => isset($headers['Strict-Transport-Security']),
                'Content-Security-Policy' => isset($headers['Content-Security-Policy']),
                'X-Frame-Options' => isset($headers['X-Frame-Options']),
                'X-Content-Type-Options' => isset($headers['X-Content-Type-Options']),
                'Referrer-Policy' => isset($headers['Referrer-Policy']),
                'Permissions-Policy' => isset($headers['Permissions-Policy']),
            ];

            $score = 100;
            $missing = [];
            foreach ($securityHeaders as $header => $present) {
                if (!$present) {
                    $score -= 15;
                    $missing[] = $header;
                }
            }

            return [
                'target' => $target,
                'score' => max(0, $score),
                'headers_present' => array_keys(array_filter($securityHeaders)),
                'headers_missing' => $missing,
                'risk_level' => $score < 50 ? 'high' : ($score < 80 ? 'medium' : 'safe'),
                'checked_at' => now()->toIso8601String(),
            ];
        } catch (\Exception $e) {
            return [
                'target' => $target,
                'score' => 0,
                'error' => 'Could not connect to domain to check headers.',
                'risk_level' => 'unknown',
            ];
        }
    }

    public function checkTechnology(string $url): array
    {
        $domain = parse_url($url, PHP_URL_HOST) ?? $url;
        $target = "https://" . preg_replace('/^https?:\/\//', '', trim($domain));

        $tech = [];
        try {
            $response = Http::timeout(5)->get($target);
            $headers = $response->headers();
            $html = $response->body();

            if (isset($headers['Server'])) {
                $tech['Server'] = $headers['Server'][0];
            }
            if (isset($headers['X-Powered-By'])) {
                $tech['Framework'] = $headers['X-Powered-By'][0];
            }
            if (stripos($html, 'wp-content') !== false) {
                $tech['CMS'] = 'WordPress';
            }
            if (stripos($html, 'Shopify.theme') !== false) {
                $tech['CMS'] = 'Shopify';
            }
            if (stripos($html, 'React') !== false || stripos($html, 'data-reactroot') !== false) {
                $tech['Frontend'] = 'React';
            }

            return [
                'target' => $target,
                'detected_technologies' => $tech,
                'checked_at' => now()->toIso8601String(),
            ];
        } catch (\Exception $e) {
            return [
                'target' => $target,
                'error' => 'Could not analyze technology.',
            ];
        }
    }

    public function checkRedirects(string $url): array
    {
        $target = preg_match('/^https?:\/\//', $url) ? $url : "http://" . $url;
        $chain = [];

        try {
            $ch = curl_init($target);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HEADER, true);
            curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
            curl_setopt($ch, CURLOPT_TIMEOUT, 5);

            $currentUrl = $target;
            $hops = 0;

            while ($hops < 10) {
                $chain[] = $currentUrl;
                curl_setopt($ch, CURLOPT_URL, $currentUrl);
                $response = curl_exec($ch);

                if ($response === false) break;

                $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                if ($httpCode >= 300 && $httpCode < 400) {
                    $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
                    $header = substr($response, 0, $headerSize);

                    if (preg_match('/^Location:\s*(.+)$/im', $header, $matches)) {
                        $redirectUrl = trim($matches[1]);
                        if (!preg_match('/^https?:\/\//', $redirectUrl)) {
                            // Handle relative redirects
                            $parsed = parse_url($currentUrl);
                            $base = $parsed['scheme'] . '://' . $parsed['host'];
                            $redirectUrl = $base . (str_starts_with($redirectUrl, '/') ? '' : '/') . $redirectUrl;
                        }
                        $currentUrl = $redirectUrl;
                        $hops++;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
            curl_close($ch);

            $isSuspicious = $hops > 3;

            return [
                'original_url' => $target,
                'final_url' => $currentUrl,
                'redirect_chain' => $chain,
                'hop_count' => $hops,
                'risk_level' => $isSuspicious ? 'high' : 'safe',
                'checked_at' => now()->toIso8601String(),
            ];
        } catch (\Exception $e) {
            return [
                'error' => 'Failed to trace redirects.',
            ];
        }
    }

    public function checkPhoneNumber(string $phone): array
    {
        $cleanPhone = preg_replace('/[^0-9+]/', '', $phone);

        // Basic heuristic placeholder
        $isTollFree = preg_match('/^\+?(1)?(800|888|877|866|855|844|833)/', $cleanPhone);
        $isPremium = preg_match('/^\+?(1)?(900)/', $cleanPhone);

        $risk = 'safe';
        $reason = 'Standard number format';

        if ($isPremium) {
            $risk = 'high';
            $reason = 'Premium rate number often used in scams';
        } else if ($isTollFree) {
            $risk = 'medium';
            $reason = 'Toll-free number (often impersonated in tech support scams)';
        } else if (strlen($cleanPhone) < 10) {
            $risk = 'high';
            $reason = 'Suspiciously short number';
        }

        return [
            'phone_number' => $cleanPhone,
            'is_toll_free' => $isTollFree,
            'is_premium' => $isPremium,
            'risk_level' => $risk,
            'reason' => $reason,
            'checked_at' => now()->toIso8601String(),
        ];
    }

    public function checkSocialMediaScam(string $urlOrHandle): array
    {
        $input = trim($urlOrHandle);
        $risk = 'safe';
        $reasons = [];

        // Check for homoglyphs or typosquatting in common social domains
        $brands = ['facebook', 'twitter', 'instagram', 'linkedin', 'tiktok', 'youtube'];
        $domain = parse_url($input, PHP_URL_HOST) ?? $input;

        foreach ($brands as $brand) {
            // If it looks like the brand but isn't exact
            if (stripos($domain, $brand) !== false && $domain !== $brand . '.com' && $domain !== 'www.' . $brand . '.com') {
                $risk = 'high';
                $reasons[] = "Impersonating {$brand} (Typosquatting)";
            }
        }

        if (preg_match('/(giveaway|support|helpdesk|admin|official)[\-_]?\d+/i', $input)) {
            $risk = 'medium';
            $reasons[] = "Handle contains suspicious patterns often used by scammers.";
        }

        return [
            'input' => $input,
            'risk_level' => empty($reasons) ? 'safe' : $risk,
            'reasons' => empty($reasons) ? ['Appears normal'] : $reasons,
            'checked_at' => now()->toIso8601String(),
        ];
    }
}
