<?php

namespace App\Services\ML;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class MLService
{
    protected string $mlApiUrl;
    protected string $mlSecret;

    public function __construct()
    {
        $this->mlApiUrl = rtrim(env('ML_API_URL', 'http://127.0.0.1:8001'), '/');
        $this->mlSecret = env('ML_API_SECRET', 'blockbord_ml_secret_key');
    }

    public function predictScamScore(string $content, ?string $url = null): array
    {
        try {
            $response = Http::timeout(3)
                ->retry(2, 100)
                ->withHeaders([
                    'X-ML-Secret' => $this->mlSecret,
                    'Accept' => 'application/json',
                ])
                ->post("{$this->mlApiUrl}/predict", [
                    'content' => $content,
                    'url' => $url,
                ]);

            if ($response->successful()) {
                return $response->json();
            }

            Log::warning("Python ML Service returned status {$response->status()}: {$response->body()}");
        } catch (\Exception $e) {
            Log::error("Python ML Service Connection Error: " . $e->getMessage());
        }

        // Graceful Heuristic Fallback if Python ML microservice is offline
        $score = 0.15;
        if (stripos($content, 'urgent') !== false || stripos($content, 'verify') !== false) {
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
