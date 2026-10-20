<?php

namespace App\Services\ML;

use Illuminate\Support\Facades\Log;

class MLService
{
    protected string $mlApiUrl;
    protected string $mlSecret;

    public function __construct()
    {
        $this->mlApiUrl = rtrim(env('ML_API_URL', 'http://127.0.0.1:8001'), '/');
        $this->mlSecret = env('ML_API_SECRET', '');
    }

    public function predictScamScore(string $content, ?string $url = null): array
    {
        try {
            $payload = json_encode([
                'content' => $content,
                'url' => $url,
            ]);

            $ch = curl_init("{$this->mlApiUrl}/predict");
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
            curl_setopt($ch, CURLOPT_HTTPHEADER, [
                'Content-Type: application/json',
                'X-ML-Secret: ' . $this->mlSecret,
                'Accept: application/json',
                'Content-Length: ' . strlen($payload)
            ]);
            curl_setopt($ch, CURLOPT_TIMEOUT, 3);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);

            $responseBody = curl_exec($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);

            if ($httpCode >= 200 && $httpCode < 300 && $responseBody) {
                $decoded = json_decode($responseBody, true);
                if (is_array($decoded)) {
                    return $decoded;
                }
            }
        } catch (\Throwable $e) {
            Log::error("Python ML Service Connection Error: " . $e->getMessage());
        }

        // Graceful Heuristic Model Fallback if Python ML microservice is offline
        $score = 0.15;
        if (stripos($content, 'urgent') !== false || stripos($content, 'verify') !== false || stripos($content, 'login') !== false) {
            $score += 0.45;
        }

        return [
            'probability' => $score,
            'risk_level' => $score >= 0.7 ? 'high' : ($score >= 0.35 ? 'medium' : 'safe'),
            'features' => ['fallback_heuristics_active' => true],
            'model_version' => 'xgboost_v2_fallback',
        ];
    }
}
