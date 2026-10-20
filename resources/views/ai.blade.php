@extends('layouts.app')

@section('title', 'AI Cyber Assistant Workspace — Block Bord AI')

@section('content')
<div style="display: flex; min-height: calc(100vh - 70px); background: #060814; color: #f8fafc;">
  <x-sidebar />

  <div style="flex: 1; display: flex; overflow: hidden; position: relative;">
    
    <!-- Left: Conversation History Threads Panel -->
    <aside style="width: 280px; background: rgba(10, 14, 28, 0.95); border-right: 1px solid rgba(99, 102, 241, 0.15); display: flex; flex-direction: column; flex-shrink: 0;">
      <div style="padding: 1.25rem; border-bottom: 1px solid rgba(255, 255, 255, 0.05); display: flex; justify-content: space-between; align-items: center;">
        <span style="font-weight: 800; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; color: #94a3b8;">
          Threat Threads
        </span>
        <button type="button" onclick="startNewChat()" style="background: linear-gradient(135deg, #6366f1 0%, #a855f7 100%); color: #fff; border: none; padding: 6px 12px; border-radius: 8px; font-size: 0.78rem; font-weight: 700; cursor: pointer; display: flex; align-items: center; gap: 4px; box-shadow: 0 2px 10px rgba(99, 102, 241, 0.3);">
          <span>+</span> New Chat
        </button>
      </div>

      <!-- Threads List -->
      <div id="conversationsList" style="flex: 1; overflow-y: auto; padding: 0.75rem;">
        @if(isset($conversations) && $conversations->isNotEmpty())
          @foreach($conversations as $conv)
            <div id="conv-item-{{ $conv->id }}" onclick="switchConversation({{ $conv->id }})" class="conv-item {{ (isset($activeConversation) && $activeConversation && $activeConversation->id == $conv->id) ? 'active' : '' }}" style="display: flex; align-items: center; justify-content: space-between; padding: 10px 12px; border-radius: 10px; margin-bottom: 6px; cursor: pointer; transition: all 0.2s; border: 1px solid {{ (isset($activeConversation) && $activeConversation && $activeConversation->id == $conv->id) ? 'rgba(99, 102, 241, 0.4)' : 'transparent' }}; background: {{ (isset($activeConversation) && $activeConversation && $activeConversation->id == $conv->id) ? 'rgba(99, 102, 241, 0.15)' : 'transparent' }};">
              <div style="flex: 1; min-width: 0; margin-right: 8px;">
                <div style="font-size: 0.82rem; font-weight: 600; color: #fff; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                  💬 {{ $conv->title }}
                </div>
                <div style="font-size: 0.68rem; color: #64748b; margin-top: 2px;">
                  {{ $conv->updated_at->diffForHumans() }}
                </div>
              </div>
              <button type="button" onclick="event.stopPropagation(); deleteConversation({{ $conv->id }})" title="Delete thread" style="background: none; border: none; color: #64748b; cursor: pointer; padding: 4px; border-radius: 4px; display: flex; align-items: center;" onmouseover="this.style.color='#ef4444'" onmouseout="this.style.color='#64748b'">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
              </button>
            </div>
          @endforeach
        @else
          <div id="no-history-msg" style="padding: 2rem 1rem; text-align: center; color: #64748b; font-size: 0.8rem;">
            No past chat sessions.<br>Ask a security question to begin!
          </div>
        @endif
      </div>
    </aside>

    <!-- Right: Main Chat Canvas -->
    <main style="flex: 1; display: flex; flex-direction: column; background: #060814; position: relative;">

      <!-- AI Header Bar -->
      <div style="padding: 1rem 2rem; background: rgba(15, 23, 42, 0.9); backdrop-filter: blur(16px); border-bottom: 1px solid rgba(99, 102, 241, 0.2); display: flex; align-items: center; justify-content: space-between;">
        <div style="display: flex; align-items: center; gap: 12px;">
          <div style="width: 40px; height: 40px; background: rgba(99, 102, 241, 0.2); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 1.25rem; border: 1px solid rgba(99, 102, 241, 0.4);">
            🤖
          </div>
          <div>
            <h2 id="chatHeading" style="color: #fff; font-size: 1.1rem; font-weight: 800; margin: 0;">
              {{ (isset($activeConversation) && $activeConversation) ? $activeConversation->title : 'Block Bord Cyber AI Assistant' }}
            </h2>
            <span style="color: #94a3b8; font-size: 0.78rem;">
              Multi-LLM Engine: Google Gemini 2.5 Flash + OpenAI + Heuristic Shield Fallback
            </span>
          </div>
        </div>

        <div style="display: flex; align-items: center; gap: 8px;">
          <span style="display: flex; align-items: center; gap: 6px; background: rgba(16, 185, 129, 0.15); color: #10b981; font-weight: 700; padding: 5px 12px; border-radius: 9999px; font-size: 0.72rem; border: 1px solid rgba(16, 185, 129, 0.3);">
            <span style="width: 6px; height: 6px; background: #10b981; border-radius: 50%;"></span>
            Active
          </span>
        </div>
      </div>

      <!-- Suggested Security Prompt Chips -->
      <div style="padding: 0.75rem 2rem; background: rgba(12, 15, 36, 0.6); border-bottom: 1px solid rgba(255,255,255,0.05); display: flex; gap: 8px; flex-wrap: wrap; align-items: center;">
        <span style="color: #64748b; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;">Prompt Suggestions:</span>
        <button type="button" onclick="usePrompt('Is this URL safe? http://free-crypto-giveaway-claim.net')" style="background: rgba(99, 102, 241, 0.1); color: #a5b4fc; border: 1px solid rgba(99, 102, 241, 0.25); padding: 4px 10px; border-radius: 6px; font-size: 0.78rem; cursor: pointer;">
          Crypto scam check
        </button>
        <button type="button" onclick="usePrompt('Analyze this SMS: Your bank account is suspended, click http://bit.ly/bank-fix')" style="background: rgba(239, 68, 68, 0.1); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.25); padding: 4px 10px; border-radius: 6px; font-size: 0.78rem; cursor: pointer;">
          Bank SMS fraud
        </button>
        <button type="button" onclick="usePrompt('How do I check if my email SPF and DKIM headers pass?')" style="background: rgba(99, 102, 241, 0.1); color: #a5b4fc; border: 1px solid rgba(99, 102, 241, 0.25); padding: 4px 10px; border-radius: 6px; font-size: 0.78rem; cursor: pointer;">
          SPF / DKIM guide
        </button>
        <button type="button" onclick="usePrompt('How can I tell if a website has a legitimate SSL certificate?')" style="background: rgba(16, 185, 129, 0.1); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.25); padding: 4px 10px; border-radius: 6px; font-size: 0.78rem; cursor: pointer;">
          SSL hygiene
        </button>
      </div>

      <!-- Chat Messages Scroll Container -->
      <div id="chatContainer" style="flex: 1; padding: 2rem; overflow-y: auto; display: flex; flex-direction: column; gap: 1.25rem;">

        <!-- Default Welcome Greeting -->
        <div class="ai-bubble" style="align-self: flex-start; max-width: 80%; background: rgba(15, 23, 42, 0.85); color: #e2e8f0; padding: 1.25rem 1.5rem; border-radius: 16px; border: 1px solid rgba(99, 102, 241, 0.2); box-shadow: 0 4px 15px rgba(0,0,0,0.3); line-height: 1.6;">
          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
            <div style="display: flex; align-items: center; gap: 8px; font-weight: 700; color: #a5b4fc; font-size: 0.85rem;">
              🤖 Block Bord Cyber AI Assistant
            </div>
            <span style="font-size: 0.65rem; background: rgba(99, 102, 241, 0.2); color: #c7d2fe; padding: 2px 8px; border-radius: 12px; font-weight: 700;">GEMINI 2.5 READY</span>
          </div>
          <div>
            Hello! I am your <strong>Block Bord Cybersecurity & Threat Intelligence Assistant</strong>. I am trained to evaluate suspicious websites, verify payment identifiers, analyze SMS/email social engineering, and provide actionable security hardening advice. How can I assist your defense today?
          </div>
        </div>

        <!-- Render existing thread messages if active -->
        @if(isset($activeConversation) && $activeConversation && $activeConversation->messages->isNotEmpty())
          @foreach($activeConversation->messages as $msg)
            @if($msg->role === 'user')
              <div style="align-self: flex-end; max-width: 75%; background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%); color: #fff; padding: 1rem 1.4rem; border-radius: 16px; font-weight: 500; box-shadow: 0 4px 15px rgba(99,102,241,0.3); line-height: 1.5;">
                {{ $msg->content }}
              </div>
            @else
              <div class="ai-bubble" style="align-self: flex-start; max-width: 80%; background: rgba(15, 23, 42, 0.85); color: #e2e8f0; padding: 1.25rem 1.5rem; border-radius: 16px; border: 1px solid rgba(99, 102, 241, 0.2); box-shadow: 0 4px 15px rgba(0,0,0,0.3); line-height: 1.6;">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
                  <div style="display: flex; align-items: center; gap: 8px; font-weight: 700; color: #a5b4fc; font-size: 0.85rem;">
                    🤖 Block Bord AI Assistant
                  </div>
                  <span style="font-size: 0.65rem; background: rgba(99, 102, 241, 0.2); color: #c7d2fe; padding: 2px 8px; border-radius: 12px; font-weight: 700;">
                    {{ strtoupper($activeConversation->provider ?? 'GEMINI') }}
                  </span>
                </div>
                <div class="message-body">{!! nl2br(e($msg->content)) !!}</div>
              </div>
            @endif
          @endforeach
        @endif

      </div>

      <!-- Input Bar -->
      <div style="padding: 1.25rem 2rem; background: rgba(15, 23, 42, 0.95); border-top: 1px solid rgba(99, 102, 241, 0.2);">
        <form id="aiChatForm" style="display: flex; gap: 12px; max-width: 1100px; margin: 0 auto;">
          @csrf
          <input type="hidden" id="conversationId" value="{{ (isset($activeConversation) && $activeConversation) ? $activeConversation->id : '' }}">
          <input type="text" id="chatInput" placeholder="Ask a security question, paste a link or scam message..." required autocomplete="off" style="flex: 1; padding: 0.9rem 1.4rem; border-radius: 12px; border: 1.5px solid rgba(99, 102, 241, 0.3); background: #060814; color: #fff; font-size: 0.95rem; outline: none; transition: border-color 0.2s;" onfocus="this.style.borderColor='#6366f1'" onblur="this.style.borderColor='rgba(99,102,241,0.3)'">
          <button type="submit" id="btnSend" style="padding: 0.9rem 1.8rem; background: linear-gradient(135deg, #6366f1 0%, #d946ef 100%); color: #fff; font-weight: 800; font-size: 0.95rem; border: none; border-radius: 12px; cursor: pointer; box-shadow: 0 4px 20px rgba(99, 102, 241, 0.4); white-space: nowrap; display: flex; align-items: center; gap: 6px;">
            <span>Send</span> 🚀
          </button>
        </form>
      </div>

    </main>
  </div>
</div>
@endsection

@section('extra_scripts')
<script>
let currentConversationId = document.getElementById('conversationId').value || null;

function usePrompt(text) {
  const input = document.getElementById('chatInput');
  input.value = text;
  input.focus();
}

function startNewChat() {
  currentConversationId = null;
  document.getElementById('conversationId').value = '';
  document.getElementById('chatHeading').textContent = 'Block Bord Cyber AI Assistant';

  // Reset active classes in list
  document.querySelectorAll('.conv-item').forEach(el => {
    el.style.borderColor = 'transparent';
    el.style.backgroundColor = 'transparent';
  });

  // Clear chat window back to welcome
  const container = document.getElementById('chatContainer');
  container.innerHTML = `
    <div class="ai-bubble" style="align-self: flex-start; max-width: 80%; background: rgba(15, 23, 42, 0.85); color: #e2e8f0; padding: 1.25rem 1.5rem; border-radius: 16px; border: 1px solid rgba(99, 102, 241, 0.2); box-shadow: 0 4px 15px rgba(0,0,0,0.3); line-height: 1.6;">
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
        <div style="display: flex; align-items: center; gap: 8px; font-weight: 700; color: #a5b4fc; font-size: 0.85rem;">
          🤖 Block Bord Cyber AI Assistant
        </div>
        <span style="font-size: 0.65rem; background: rgba(99, 102, 241, 0.2); color: #c7d2fe; padding: 2px 8px; border-radius: 12px; font-weight: 700;">NEW CONSULTATION</span>
      </div>
      <div>
        Hello! I am ready for a new threat consultation. Paste any suspicious link, sender message, or security question to begin analysis.
      </div>
    </div>
  `;
}

async function switchConversation(id) {
  currentConversationId = id;
  document.getElementById('conversationId').value = id;

  // Highlight selected in sidebar
  document.querySelectorAll('.conv-item').forEach(el => {
    el.style.borderColor = 'transparent';
    el.style.backgroundColor = 'transparent';
  });
  const activeEl = document.getElementById(`conv-item-${id}`);
  if (activeEl) {
    activeEl.style.borderColor = 'rgba(99, 102, 241, 0.4)';
    activeEl.style.backgroundColor = 'rgba(99, 102, 241, 0.15)';
  }

  const container = document.getElementById('chatContainer');
  container.innerHTML = '<div style="text-align: center; color: #94a3b8; padding: 2rem;">⚡ Loading conversation history...</div>';

  try {
    const res = await fetch(`/ai/conversation/${id}`);
    const data = await res.json();
    if (data.success && data.conversation) {
      document.getElementById('chatHeading').textContent = data.conversation.title || 'Security Consultation';
      container.innerHTML = '';

      const msgs = data.conversation.messages || [];
      if (msgs.length === 0) {
        container.innerHTML = '<div style="color: #64748b; text-align: center; padding: 2rem;">No messages in this thread yet.</div>';
      } else {
        msgs.forEach(m => {
          if (m.role === 'user') {
            appendUserMessage(m.content);
          } else {
            appendAiMessage(m.content, data.conversation.provider);
          }
        });
      }
      container.scrollTop = container.scrollHeight;
    }
  } catch (err) {
    container.innerHTML = '<div style="color: #ef4444; text-align: center; padding: 2rem;">Could not load conversation history.</div>';
  }
}

async function deleteConversation(id) {
  if (!confirm("Are you sure you want to delete this conversation?")) return;

  try {
    const res = await fetch(`/ai/conversation/${id}`, {
      method: 'DELETE',
      headers: {
        'X-CSRF-TOKEN': '{{ csrf_token() }}'
      }
    });
    const data = await res.json();
    if (data.success) {
      const item = document.getElementById(`conv-item-${id}`);
      if (item) item.remove();

      if (currentConversationId == id) {
        startNewChat();
      }
    }
  } catch (err) {
    alert("Error deleting conversation.");
  }
}

function renderFormattedText(text) {
  if (!text) return '';
  let safe = text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  // Headers
  safe = safe.replace(/^### (.*$)/gim, '<h4 style="color: #c7d2fe; margin: 10px 0 6px; font-size: 0.95rem;">$1</h4>');
  safe = safe.replace(/^#### (.*$)/gim, '<h5 style="color: #e0e7ff; margin: 8px 0 4px; font-size: 0.88rem;">$1</h5>');
  // Bold
  safe = safe.replace(/\*\*(.*?)\*\*/gim, '<strong style="color: #fff;">$1</strong>');
  // Inline code
  safe = safe.replace(/`([^`]+)`/gim, '<code style="background: rgba(0,0,0,0.4); padding: 2px 6px; border-radius: 4px; color: #f472b6; font-size: 0.85em;">$1</code>');
  // Bullet lists
  safe = safe.replace(/^\s*-\s+(.*$)/gim, '<li style="margin-left: 18px; margin-bottom: 4px;">$1</li>');
  // Line breaks
  safe = safe.replace(/\n/gim, '<br>');

  return safe;
}

function appendUserMessage(msg) {
  const container = document.getElementById('chatContainer');
  const userDiv = document.createElement('div');
  userDiv.style.cssText = 'align-self: flex-end; max-width: 75%; background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%); color: #fff; padding: 1rem 1.4rem; border-radius: 16px; font-weight: 500; box-shadow: 0 4px 15px rgba(99,102,241,0.3); line-height: 1.5; word-break: break-word;';
  userDiv.textContent = msg;
  container.appendChild(userDiv);
  container.scrollTop = container.scrollHeight;
}

function appendAiMessage(reply, provider = 'gemini') {
  const container = document.getElementById('chatContainer');
  const aiDiv = document.createElement('div');
  aiDiv.className = 'ai-bubble';
  aiDiv.style.cssText = 'align-self: flex-start; max-width: 80%; background: rgba(15, 23, 42, 0.85); color: #e2e8f0; padding: 1.25rem 1.5rem; border-radius: 16px; border: 1px solid rgba(99, 102, 241, 0.2); box-shadow: 0 4px 15px rgba(0,0,0,0.3); line-height: 1.6; word-break: break-word;';

  const provLabel = (provider || 'GEMINI').toUpperCase();
  const badgeColor = provLabel.includes('GEMINI') ? '#c7d2fe' : (provLabel.includes('OPENAI') ? '#86efac' : '#fde047');

  aiDiv.innerHTML = `
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
      <div style="display: flex; align-items: center; gap: 8px; font-weight: 700; color: #a5b4fc; font-size: 0.85rem;">
        🤖 Block Bord AI Assistant
      </div>
      <span style="font-size: 0.65rem; background: rgba(99, 102, 241, 0.2); color: ${badgeColor}; padding: 2px 8px; border-radius: 12px; font-weight: 700;">
        ${provLabel}
      </span>
    </div>
    <div class="message-content">${renderFormattedText(reply)}</div>
  `;
  container.appendChild(aiDiv);
  container.scrollTop = container.scrollHeight;
}

document.getElementById('aiChatForm').addEventListener('submit', async function(e) {
  e.preventDefault();
  const input = document.getElementById('chatInput');
  const msg = input.value.trim();
  if (!msg) return;

  const btnSend = document.getElementById('btnSend');
  btnSend.disabled = true;
  btnSend.style.opacity = '0.6';

  appendUserMessage(msg);
  input.value = '';

  const container = document.getElementById('chatContainer');
  const typingDiv = document.createElement('div');
  typingDiv.id = 'typingIndicator';
  typingDiv.style.cssText = 'align-self: flex-start; background: rgba(15,23,42,0.8); color: #94a3b8; padding: 0.85rem 1.25rem; border-radius: 12px; font-size: 0.875rem; border: 1px solid rgba(99,102,241,0.2);';
  typingDiv.innerHTML = '⚡ <em>AI is analyzing threat telemetry...</em>';
  container.appendChild(typingDiv);
  container.scrollTop = container.scrollHeight;

  try {
    const res = await fetch('{{ route("ai.chat") }}', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF-TOKEN': '{{ csrf_token() }}'
      },
      body: JSON.stringify({
        message: msg,
        conversation_id: currentConversationId
      })
    });

    const data = await res.json();
    document.getElementById('typingIndicator')?.remove();

    if (data.success) {
      appendAiMessage(data.reply, data.provider);

      // Update or set active conversation ID
      if (data.conversation_id) {
        currentConversationId = data.conversation_id;
        document.getElementById('conversationId').value = data.conversation_id;
        document.getElementById('chatHeading').textContent = data.title || 'Security Consultation';

        // Add to sidebar if not present
        if (!document.getElementById(`conv-item-${data.conversation_id}`)) {
          document.getElementById('no-history-msg')?.remove();
          const list = document.getElementById('conversationsList');
          const newEl = document.createElement('div');
          newEl.id = `conv-item-${data.conversation_id}`;
          newEl.className = 'conv-item active';
          newEl.onclick = () => switchConversation(data.conversation_id);
          newEl.style.cssText = 'display: flex; align-items: center; justify-content: space-between; padding: 10px 12px; border-radius: 10px; margin-bottom: 6px; cursor: pointer; border: 1px solid rgba(99, 102, 241, 0.4); background: rgba(99, 102, 241, 0.15);';
          newEl.innerHTML = `
            <div style="flex: 1; min-width: 0; margin-right: 8px;">
              <div style="font-size: 0.82rem; font-weight: 600; color: #fff; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;">
                💬 ${data.title || 'Security Chat'}
              </div>
              <div style="font-size: 0.68rem; color: #64748b; margin-top: 2px;">Just now</div>
            </div>
            <button type="button" onclick="event.stopPropagation(); deleteConversation(${data.conversation_id})" style="background: none; border: none; color: #64748b; cursor: pointer; padding: 4px;">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg>
            </button>
          `;
          list.prepend(newEl);
        }
      }
    } else {
      appendAiMessage("⚠️ " + (data.message || "An error occurred while analyzing your request."), "fallback");
    }
  } catch (err) {
    document.getElementById('typingIndicator')?.remove();
    appendAiMessage("⚠️ Network error communicating with Block Bord AI. Please try again.", "fallback");
  } finally {
    btnSend.disabled = false;
    btnSend.style.opacity = '1';
    input.focus();
  }
});
</script>
@endsection
