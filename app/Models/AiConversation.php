<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class AiConversation extends Model
{
    use HasFactory;

    protected $fillable = [
        'user_id',
        'user_prompt',
        'ai_response',
        'provider',
        'model',
    ];

    public function user()
    {
        return $this->belongsTo(User::class);
    }

    public function messages()
    {
        return $this->hasMany(AiMessage::class, 'conversation_id')->orderBy('created_at', 'asc');
    }

    /**
     * Get a human-readable title for this conversation thread.
     */
    public function getTitleAttribute(): string
    {
        if (!empty($this->user_prompt)) {
            $cleaned = trim(preg_replace('/\s+/', ' ', $this->user_prompt));
            return mb_strlen($cleaned) > 42 ? mb_substr($cleaned, 0, 42) . '…' : $cleaned;
        }

        $firstMsg = $this->messages()->first();
        if ($firstMsg && !empty($firstMsg->content)) {
            $cleaned = trim(preg_replace('/\s+/', ' ', $firstMsg->content));
            return mb_strlen($cleaned) > 42 ? mb_substr($cleaned, 0, 42) . '…' : $cleaned;
        }

        return 'Security Chat #' . $this->id;
    }

    /**
     * Get past message turns formatted for multi-turn LLM context.
     */
    public function getContextForLLM(int $limit = 10): array
    {
        $msgs = $this->messages()
            ->latest('id')
            ->take($limit)
            ->get()
            ->reverse();

        $context = [];
        foreach ($msgs as $m) {
            $context[] = [
                'role' => $m->role,
                'content' => $m->content,
            ];
        }
        return $context;
    }
}
