<?php

namespace App\Services\AI;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class OpenAIService implements AIServiceInterface
{
    protected string $apiKey;
    protected string $model;

    public function __construct()
    {
        $this->apiKey = env('OPENAI_API_KEY', '');
        $this->model = env('OPENAI_MODEL', 'gpt-4o-mini');
    }

    public function generateResponse(string $prompt, array $context = []): array
    {
        if (empty($this->apiKey) || $this->apiKey === 'your_openai_api_key_here') {
            throw new \Exception('OpenAI API key is missing or unconfigured.');
        }

        $response = Http::timeout(8)
            ->withToken($this->apiKey)
            ->post('https://api.openai.com/v1/chat/completions', [
                'model' => $this->model,
                'messages' => [
                    ['role' => 'system', 'content' => 'You are Block Bord AI, an expert cybersecurity AI assistant.'],
                    ['role' => 'user', 'content' => $prompt]
                ],
                'temperature' => 0.4,
            ]);

        if ($response->failed()) {
            Log::warning("OpenAI API Error: Status {$response->status()} - {$response->body()}");
            throw new \Exception("OpenAI API returned status {$response->status()}");
        }

        $json = $response->json();
        $text = $json['choices'][0]['message']['content'] ?? '';

        return [
            'provider' => 'openai',
            'model' => $this->model,
            'text' => $text,
            'success' => true,
        ];
    }
}
