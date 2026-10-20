<?php

namespace App\Http\Controllers;

use App\Services\AI\AIFallbackManager;
use App\Models\AiConversation;
use App\Models\AiMessage;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class AiAssistantController extends Controller
{
    protected AIFallbackManager $aiManager;

    public function __construct(AIFallbackManager $aiManager)
    {
        $this->aiManager = $aiManager;
    }

    /**
     * Show the main AI Cyber Assistant Workspace.
     */
    public function showAiPage(Request $request)
    {
        $userId = Auth::id();
        $conversations = collect();
        $activeConversation = null;

        if ($userId) {
            $conversations = AiConversation::where('user_id', $userId)
                ->withCount('messages')
                ->latest('updated_at')
                ->take(30)
                ->get();

            $activeId = $request->query('conversation_id');
            if ($activeId) {
                $activeConversation = AiConversation::where('user_id', $userId)
                    ->with('messages')
                    ->find($activeId);
            }

            if (!$activeConversation && $conversations->isNotEmpty()) {
                $activeConversation = $conversations->first();
                $activeConversation->load('messages');
            }
        }

        return view('ai', compact('conversations', 'activeConversation'));
    }

    /**
     * Multi-turn chat message submission.
     */
    public function chat(Request $request)
    {
        $prompt = trim($request->input('message') ?? $request->input('prompt') ?? '');
        if (empty($prompt)) {
            return response()->json(['success' => false, 'message' => 'Prompt cannot be empty'], 400);
        }

        $userId = Auth::id();
        $conversationId = $request->input('conversation_id');
        $conversation = null;

        // Find existing conversation or create new
        if ($conversationId) {
            $conversation = AiConversation::where('user_id', $userId)->find($conversationId);
            if (!$conversation) {
                return response()->json(['success' => false, 'message' => 'Conversation not found'], 404);
            }
        }

        if (!$conversation) {
            $conversation = AiConversation::create([
                'user_id' => $userId,
                'user_prompt' => $prompt,
                'ai_response' => '',
                'provider' => 'pending',
                'model' => 'default',
            ]);
        }

        // Get past multi-turn context (last 10 messages)
        $context = $conversation->getContextForLLM(10);

        // Record User Message
        AiMessage::create([
            'conversation_id' => $conversation->id,
            'role' => 'user',
            'content' => $prompt,
        ]);

        // Query AI Engine (Gemini -> OpenAI -> Local Heuristic Fallback)
        $result = $this->aiManager->ask($prompt, $context);
        $replyText = $result['text'] ?? '';
        $provider = $result['provider'] ?? 'fallback';
        $model = $result['model'] ?? 'default';

        // Record Model Message
        AiMessage::create([
            'conversation_id' => $conversation->id,
            'role' => 'assistant',
            'content' => $replyText,
        ]);

        // Update conversation summary
        $conversation->update([
            'ai_response' => $replyText,
            'provider' => $provider,
            'model' => $model,
        ]);
        $conversation->touch();

        return response()->json([
            'success' => true,
            'conversation_id' => $conversation->id,
            'title' => $conversation->title,
            'reply' => $replyText,
            'provider' => $provider,
            'model' => $model,
            'data' => $result,
        ]);
    }

    /**
     * Retrieve full message history of a specific conversation via AJAX.
     */
    public function getConversation($id)
    {
        $userId = Auth::id();
        $conversation = AiConversation::with('messages')
            ->where('user_id', $userId)
            ->find($id);

        if (!$conversation) {
            return response()->json(['success' => false, 'message' => 'Conversation not found'], 404);
        }

        return response()->json([
            'success' => true,
            'conversation' => [
                'id' => $conversation->id,
                'title' => $conversation->title,
                'provider' => $conversation->provider,
                'model' => $conversation->model,
                'messages' => $conversation->messages,
            ]
        ]);
    }

    /**
     * Delete an entire conversation thread.
     */
    public function deleteConversation($id)
    {
        $userId = Auth::id();
        $conversation = AiConversation::where('user_id', $userId)->find($id);

        if (!$conversation) {
            return response()->json(['success' => false, 'message' => 'Conversation not found'], 404);
        }

        $conversation->delete();

        return response()->json([
            'success' => true,
            'message' => 'Conversation deleted successfully'
        ]);
    }

    /**
     * Legacy scam text analyzer tool.
     */
    public function analyzeScam(Request $request)
    {
        $text = $request->input('content') ?? $request->input('text');
        if (!$text) {
            return response()->json(['success' => false, 'message' => 'Content is required'], 400);
        }

        $prompt = "Analyze the following message for potential phishing, scam intent, or fraud indicators:\n\n{$text}";
        $result = $this->aiManager->ask($prompt);

        AiConversation::create([
            'user_id' => Auth::id(),
            'user_prompt' => $text,
            'ai_response' => $result['text'] ?? '',
            'provider' => $result['provider'] ?? 'unknown',
            'model' => $result['model'] ?? 'default',
        ]);

        return response()->json([
            'success' => true,
            'data' => $result,
            'analysis' => $result['text'],
        ]);
    }
}
