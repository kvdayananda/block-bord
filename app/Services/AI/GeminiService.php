<?php

namespace App\Services\AI;

use Illuminate\Support\Facades\Log;

class GeminiService implements AIServiceInterface
{
    protected string $apiKey;
    protected string $model;
    protected string $systemInstruction;

    public function __construct()
    {
        $this->apiKey = env('GEMINI_API_KEY', '');
        $this->model = env('GEMINI_MODEL', 'gemini-2.5-flash');
        $this->systemInstruction = "You are Block Bord Cyber AI Assistant, an elite cybersecurity and fraud prevention intelligence assistant. "
            . "Provide direct, expert, actionable security advice. Analyze URLs, email headers, SMS scams, phishing attempts, and digital threats. "
            . "Format responses cleanly using markdown bullet points, risk ratings, and clear mitigation recommendations. "
            . "Never encourage illegal activities or hacking.";
    }

    /**
     * Generate response with multi-turn conversation support.
     *
     * @param string $prompt
     * @param array $context Array of past turns [['role' => 'user'|'model'|'assistant', 'content' => '...']]
     * @return array
     */
    public function generateResponse(string $prompt, array $context = []): array
    {
        if (empty($this->apiKey) || $this->apiKey === 'your_gemini_api_key_here') {
            throw new \Exception('Gemini API key is unconfigured.');
        }

        // Build multi-turn contents array
        $contents = [];

        foreach ($context as $msg) {
            $rawRole = strtolower($msg['role'] ?? 'user');
            $role = ($rawRole === 'model' || $rawRole === 'assistant' || $rawRole === 'ai') ? 'model' : 'user';
            $text = $msg['content'] ?? $msg['text'] ?? '';
            if (!empty($text)) {
                $contents[] = [
                    'role' => $role,
                    'parts' => [
                        ['text' => (string) $text]
                    ]
                ];
            }
        }

        // Append current user prompt
        $contents[] = [
            'role' => 'user',
            'parts' => [
                ['text' => $prompt]
            ]
        ];

        $url = "https://generativelanguage.googleapis.com/v1beta/models/{$this->model}:generateContent?key={$this->apiKey}";

        $payload = [
            'systemInstruction' => [
                'parts' => [
                    ['text' => $this->systemInstruction]
                ]
            ],
            'contents' => $contents,
            'generationConfig' => [
                'temperature' => 0.3,
                'maxOutputTokens' => 2048,
            ]
        ];

        $jsonPayload = json_encode($payload);

        // Native resilient cURL execution
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $jsonPayload,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Content-Length: ' . strlen($jsonPayload)
            ],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 12,
            CURLOPT_SSL_VERIFYPEER => true,
        ]);

        $responseBody = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($responseBody === false || !empty($curlError)) {
            Log::warning("Gemini API connection error: " . $curlError);
            throw new \Exception("Gemini API connection failed: " . $curlError);
        }

        if ($httpCode < 200 || $httpCode >= 300) {
            $cleanBody = str_replace($this->apiKey, '***', $responseBody);
            Log::warning("Gemini API Error: Status {$httpCode} - {$cleanBody}");
            throw new \Exception("Gemini API returned status {$httpCode}");
        }

        $json = json_decode($responseBody, true);
        $text = $json['candidates'][0]['content']['parts'][0]['text'] ?? '';

        if (empty($text)) {
            throw new \Exception("Gemini API returned empty candidate response");
        }

        return [
            'provider' => 'gemini',
            'model' => $this->model,
            'text' => $text,
            'success' => true,
        ];
    }
}
