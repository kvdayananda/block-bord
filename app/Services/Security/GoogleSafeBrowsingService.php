<?php

namespace App\Services\Security;

use Illuminate\Support\Facades\Log;

class GoogleSafeBrowsingService
{
    protected string $apiKey;

    public function __construct()
    {
        $this->apiKey = env('GOOGLE_SAFE_BROWSING_API_KEY', env('GOOGLE_SAFE_BROWSING_KEY', ''));
    }

    public function checkUrl(string $url): array
    {
        if (empty($this->apiKey) || $this->apiKey === 'your_google_safe_browsing_api_key_here') {
            return [
                'is_malicious' => false,
                'threat_types' => [],
                'status' => 'unconfigured',
            ];
        }

        try {
            $endpoint = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={$this->apiKey}";
            $payload = json_encode([
                'client' => [
                    'clientId' => 'blockbord-ai',
                    'clientVersion' => '2.5.0',
                ],
                'threatInfo' => [
                    'threatTypes' => [
                        'MALWARE',
                        'SOCIAL_ENGINEERING',
                        'UNWANTED_SOFTWARE',
                        'POTENTIALLY_HARMFUL_APPLICATION'
                    ],
                    'platformTypes' => ['ANY_PLATFORM'],
                    'threatEntryTypes' => ['URL'],
                    'threatEntries' => [
                        ['url' => $url]
                    ],
                ],
            ]);

            $ch = curl_init($endpoint);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json', 'Content-Length: ' . strlen($payload)]);
            curl_setopt($ch, CURLOPT_TIMEOUT, 4);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

            $responseBody = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode >= 200 && $httpCode < 300 && $responseBody) {
                $data = json_decode($responseBody, true);
                $matches = $data['matches'] ?? [];
                $threatTypes = array_column($matches, 'threatType');

                return [
                    'is_malicious' => count($matches) > 0,
                    'threat_types' => array_unique($threatTypes),
                    'status' => 'verified',
                ];
            }
        } catch (\Throwable $e) {
            Log::error("Google Safe Browsing API Error: " . $e->getMessage());
        }

        return [
            'is_malicious' => false,
            'threat_types' => [],
            'status' => 'error',
        ];
    }
}
