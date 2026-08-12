@extends('layouts.app')

@section('title', 'AI Cyber Assistant Workspace — Block Bord AI')

@section('content')
<div style="display: flex; min-height: calc(100vh - 70px); background: #060814;">
  <x-sidebar />

  <main style="flex: 1; display: flex; flex-direction: column; background: #060814; position: relative;">
    
    <!-- AI Header Bar -->
    <div style="padding: 1.25rem 2rem; background: rgba(15, 23, 42, 0.9); backdrop-filter: blur(16px); border-bottom: 1px solid rgba(99, 102, 241, 0.2); display: flex; align-items: center; justify-content: space-between;">
      <div style="display: flex; align-items: center; gap: 12px;">
        <div style="width: 40px; height: 40px; background: rgba(99, 102, 241, 0.2); border-radius: 10px; display: flex; align-items: center; justify-content: justify; align-items: center; justify-content: center; font-size: 1.25rem; border: 1px solid rgba(99, 102, 241, 0.4);">
          🤖
        </div>
        <div>
          <h2 style="color: #fff; font-size: 1.15rem; font-weight: 800; margin: 0;">Block Bord Cyber AI Assistant</h2>
          <span style="color: #94a3b8; font-size: 0.8rem;">Powered by Gemini 2.5 Flash & OpenAI Multi-LLM Engine</span>
        </div>
      </div>
      
      <div style="display: flex; align-items: center; gap: 8px; background: rgba(16, 185, 129, 0.15); color: #10b981; font-weight: 700; padding: 6px 14px; border-radius: 9999px; font-size: 0.75rem; border: 1px solid rgba(16, 185, 129, 0.3);">
        <span style="width: 7px; height: 7px; background: #10b981; border-radius: 50%; display: inline-block;"></span>
        Online & Monitoring
      </div>
    </div>

    <!-- Suggested Security Prompt Chips -->
    <div style="padding: 1rem 2rem; background: rgba(12, 15, 36, 0.6); border-bottom: 1px solid rgba(255,255,255,0.05); display: flex; gap: 10px; flex-wrap: wrap;">
      <span style="color: #64748b; font-size: 0.8rem; font-weight: 600; display: flex; align-items: center;">Try Asking:</span>
      <button type="button" onclick="usePrompt('Is this URL safe? http://free-crypto-giveaway-claim.net')" style="background: rgba(99, 102, 241, 0.1); color: #a5b4fc; border: 1px solid rgba(99, 102, 241, 0.25); padding: 5px 12px; border-radius: 8px; font-size: 0.8rem; cursor: pointer; font-weight: 500;">
        Is this crypto URL safe?
      </button>
      <button type="button" onclick="usePrompt('How do I check if my email SPF and DKIM headers pass?')" style="background: rgba(99, 102, 241, 0.1); color: #a5b4fc; border: 1px solid rgba(99, 102, 241, 0.25); padding: 5px 12px; border-radius: 8px; font-size: 0.8rem; cursor: pointer; font-weight: 500;">
        How to check SPF/DKIM headers
      </button>
      <button type="button" onclick="usePrompt('Analyze this SMS: Your bank account is suspended, click http://bit.ly/bank-fix')" style="background: rgba(239, 68, 68, 0.1); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.25); padding: 5px 12px; border-radius: 8px; font-size: 0.8rem; cursor: pointer; font-weight: 500;">
        Analyze bank SMS scam
      </button>
    </div>

    <!-- Chat Messages Scroll Container -->
    <div id="chatContainer" style="flex: 1; padding: 2rem; overflow-y: auto; display: flex; flex-direction: column; gap: 1.25rem;">
      <div style="align-self: flex-start; max-width: 75%; background: rgba(15, 23, 42, 0.8); color: #e2e8f0; padding: 1.25rem 1.5rem; border-radius: 16px; border: 1px solid rgba(99, 102, 241, 0.2); box-shadow: 0 4px 15px rgba(0,0,0,0.3); line-height: 1.6;">
        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px; font-weight: 700; color: #a5b4fc; font-size: 0.85rem;">
          🤖 Block Bord AI Assistant
        </div>
        Hello! I am your AI Cybersecurity Assistant. Ask me to inspect any suspicious website link, email header, payment SMS, or security best practice!
      </div>
    </div>

    <!-- Input Bar -->
    <div style="padding: 1.5rem 2rem; background: rgba(15, 23, 42, 0.95); border-top: 1px solid rgba(99, 102, 241, 0.2);">
      <form id="aiChatForm" style="display: flex; gap: 12px; max-width: 1000px; margin: 0 auto;">
        @csrf
        <input type="text" id="chatInput" placeholder="Ask a security question, paste a link or scam message..." required style="flex: 1; padding: 1rem 1.4rem; border-radius: 12px; border: 1.5px solid rgba(99, 102, 241, 0.3); background: #060814; color: #fff; font-size: 0.975rem; outline: none;">
        <button type="submit" style="padding: 1rem 2rem; background: linear-gradient(135deg, #6366f1 0%, #d946ef 100%); color: #fff; font-weight: 800; font-size: 0.95rem; border: none; border-radius: 12px; cursor: pointer; box-shadow: 0 4px 20px rgba(99, 102, 241, 0.4); white-space: nowrap;">
          Send Message 🚀
        </button>
      </form>
    </div>
  </main>
</div>

@section('extra_scripts')
<script>
function usePrompt(text) {
  document.getElementById('chatInput').value = text;
}

document.getElementById('aiChatForm').addEventListener('submit', async function(e) {
  e.preventDefault();
  const input = document.getElementById('chatInput');
  const msg = input.value.trim();
  if(!msg) return;

  const container = document.getElementById('chatContainer');
  
  // User speech bubble
  const userDiv = document.createElement('div');
  userDiv.style.cssText = 'align-self: flex-end; max-width: 75%; background: linear-gradient(135deg, #6366f1 0%, #4f46e5 100%); color: #fff; padding: 1.1rem 1.4rem; border-radius: 16px; font-weight: 500; box-shadow: 0 4px 15px rgba(99,102,241,0.3); line-height: 1.5;';
  userDiv.textContent = msg;
  container.appendChild(userDiv);

  input.value = '';
  container.scrollTop = container.scrollHeight;

  // Typing indicator placeholder
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
      body: JSON.stringify({ message: msg })
    });
    const data = await res.json();
    document.getElementById('typingIndicator')?.remove();

    const aiDiv = document.createElement('div');
    aiDiv.style.cssText = 'align-self: flex-start; max-width: 75%; background: rgba(15, 23, 42, 0.8); color: #e2e8f0; padding: 1.25rem 1.5rem; border-radius: 16px; border: 1px solid rgba(99, 102, 241, 0.2); box-shadow: 0 4px 15px rgba(0,0,0,0.3); line-height: 1.6;';
    aiDiv.innerHTML = `<div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px; font-weight: 700; color: #a5b4fc; font-size: 0.85rem;">🤖 Block Bord AI Assistant</div>${data.reply || data.message || 'Error processing request.'}`;
    container.appendChild(aiDiv);
    container.scrollTop = container.scrollHeight;
  } catch(err) {
    document.getElementById('typingIndicator')?.remove();
    console.error(err);
  }
});
</script>
@endsection
@endsection
