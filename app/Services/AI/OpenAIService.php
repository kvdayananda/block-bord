<?php

namespace App\Services\AI;

use Illuminate\Support\Facades\Log;

class OpenAIService implements AIServiceInterface
{
    protected string $apiKey;
    protected string $model;
    protected string $systemPrompt;

    public function __construct()
    {
        $this->apiKey = env('OPENAI_API_KEY', '');
        $this->model = env('OPENAI_MODEL', 'gpt-4o-mini');
        $this->systemPrompt = "You are Block Bord Cyber AI Assistant, an elite cybersecurity and fraud prevention intelligence assistant. "
            . "Provide direct, expert, actionable security advice. Analyze URLs, email headers, SMS scams, phishing attempts, and digital threats. "
            . "Format responses cleanly using markdown bullet points, risk ratings, and clear mitigation recommendations.";
    }

    /**
     * Generate response with multi-turn conversation support.
     *
     * @param string $prompt
     * @param array $context Array of past turns [['role' => 'user'|'assistant'|'model', 'content' => '...']]
     * @return array
     */
    public function generateResponse(string $prompt, array $context = []): array
    {
        if (empty($this->apiKey) || $this->apiKey === 'your_openai_api_key_here') {
            throw new \Exception('OpenAI API key is unconfigured.');
        }

        $messages = [
            ['role' => 'system', 'content' => $this->systemPrompt]
        ];

        foreach ($context as $msg) {
            $rawRole = strtolower($msg['role'] ?? 'user');
            $role = ($rawRole === 'model' || $rawRole === 'assistant' || $rawRole === 'ai') ? 'assistant' : 'user';
            $text = $msg['content'] ?? $msg['text'] ?? '';
            if (!empty($text)) {
                $messages[] = [
                    'role' => $role,
                    'content' => (string) $text
                ];
            }
        }

        $messages[] = [
            'role' => 'user',
            'content' => $prompt
        ];

        $payload = [
            'model' => $this->model,
            'messages' => $messages,
            'temperature' => 0.4,
            'max_tokens' => 2048,
        ];

        $jsonPayload = json_encode($payload);

        $ch = curl_init('https://api.openai.com/v1/chat/completions');
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $jsonPayload,
            CURLOPT_HTTPHEADER => [
                'Content-Type: application/json',
                'Authorization: Bearer ' . $this->apiKey,
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
            Log::warning("OpenAI API connection error: " . $curlError);
            throw new \Exception("OpenAI API connection failed: " . $curlError);
        }

        if ($httpCode < 200 || $httpCode >= 300) {
            $cleanBody = str_replace($this->apiKey, '***', $responseBody);
            Log::warning("OpenAI API Error: Status {$httpCode} - {$cleanBody}");
            throw new \Exception("OpenAI API returned status {$httpCode}");
        }

        $json = json_decode($responseBody, true);
        $text = $json['choices'][0]['message']['content'] ?? '';

        if (empty($text)) {
            throw new \Exception("OpenAI API returned empty choices response");
        }

        return [
            'provider' => 'openai',
            'model' => $this->model,
            'text' => $text,
            'success' => true,
        ];
    }
}
