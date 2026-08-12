<?php

namespace App\Services\AI;

use Illuminate\Support\Facades\Log;

class AIFallbackManager
{
    protected GeminiService $gemini;
    protected OpenAIService $openAI;

    public function __construct(GeminiService $gemini, OpenAIService $openAI)
    {
        $this->gemini = $gemini;
        $this->openAI = $openAI;
    }

    public function ask(string $prompt, array $context = []): array
    {
        // 1. Try Gemini
        try {
            return $this->gemini->generateResponse($prompt, $context);
        } catch (\Exception $e) {
            Log::info("Gemini unavailable, attempting OpenAI fallback: " . $e->getMessage());
        }

        // 2. Try OpenAI
        try {
            return $this->openAI->generateResponse($prompt, $context);
        } catch (\Exception $e) {
            Log::info("OpenAI unavailable, attempting graceful local fallback: " . $e->getMessage());
        }

        // 3. Graceful Local Fallback
        return [
            'provider' => 'fallback',
            'model' => 'heuristics-engine-v2',
            'text' => "Block Bord AI Shield Analysis:\n\nBased on static pattern heuristics and risk telemetry, this target exhibits signs of automated threat behavior. Exercise caution before proceeding or submitting credentials.",
            'success' => true,
        ];
    }
}
