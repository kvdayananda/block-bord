<?php

namespace App\Http\Controllers;

use App\Services\AI\AIFallbackManager;
use Illuminate\Http\Request;

class AiAssistantController extends Controller
{
    protected AIFallbackManager $aiManager;

    public function __construct(AIFallbackManager $aiManager)
    {
        $this->aiManager = $aiManager;
    }

    public function showAiPage()
    {
        return view('ai');
    }

    public function chat(Request $request)
    {
        $prompt = $request->input('message') ?? $request->input('prompt');
        if (!$prompt) {
            return response()->json(['success' => false, 'message' => 'Prompt cannot be empty'], 400);
        }

        $result = $this->aiManager->ask($prompt);

        return response()->json([
            'success' => true,
            'data' => $result,
            'reply' => $result['text'],
        ]);
    }

    public function analyzeScam(Request $request)
    {
        $text = $request->input('content') ?? $request->input('text');
        if (!$text) {
            return response()->json(['success' => false, 'message' => 'Content is required'], 400);
        }

        $prompt = "Analyze the following message for potential phishing, scam intent, or fraud indicators:\n\n{$text}";
        $result = $this->aiManager->ask($prompt);

        return response()->json([
            'success' => true,
            'data' => $result,
            'analysis' => $result['text'],
        ]);
    }
}
