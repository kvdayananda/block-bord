@extends('layouts.app')

@section('title', 'AI Cyber Assistant — Block Bord AI')

@section('content')
<div style="display: flex; height: calc(100vh - 70px);">
  <x-sidebar />

  <main style="flex: 1; display: flex; flex-direction: column; background: #0f0f17;">
    <div style="padding: 1.5rem; background: #1e1e2e; border-bottom: 1px solid rgba(255,255,255,0.08); display: flex; align-items: center; justify-content: space-between;">
      <h2 style="color: #fff; font-size: 1.25rem; font-weight: 700; margin: 0;">🤖 Block Bord Cyber AI Assistant</h2>
      <span style="background: rgba(16, 185, 129, 0.2); color: #10b981; font-weight: 700; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem;">Multi-Provider Engine Active</span>
    </div>

    <!-- Chat Messages Container -->
    <div id="chatContainer" style="flex: 1; padding: 2rem; overflow-y: auto; display: flex; flex-direction: column; gap: 1rem;">
      <div style="align-self: flex-start; max-width: 70%; background: #1e1e2e; color: #cbd5e1; padding: 1rem 1.25rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.05);">
        Hello! I am your AI Cybersecurity Assistant. Ask me about suspicious URLs, email headers, scam messages, or security best practices!
      </div>
    </div>

    <!-- Input Bar -->
    <div style="padding: 1.5rem; background: #1e1e2e; border-top: 1px solid rgba(255,255,255,0.08);">
      <form id="aiChatForm" style="display: flex; gap: 0.75rem;">
        @csrf
        <input type="text" id="chatInput" placeholder="Type a message or paste a suspicious link..." required style="flex: 1; padding: 0.85rem 1.25rem; border-radius: 8px; border: 1px solid #33334d; background: #11111b; color: #fff; outline: none;">
        <button type="submit" style="padding: 0.85rem 1.75rem; background: #6366f1; color: #fff; font-weight: 700; border: none; border-radius: 8px; cursor: pointer;">Send</button>
      </form>
    </div>
  </main>
</div>

@section('extra_scripts')
<script>
document.getElementById('aiChatForm').addEventListener('submit', async function(e) {
  e.preventDefault();
  const input = document.getElementById('chatInput');
  const msg = input.value.trim();
  if(!msg) return;

  const container = document.getElementById('chatContainer');
  
  // User bubble
  const userDiv = document.createElement('div');
  userDiv.style.cssText = 'align-self: flex-end; max-width: 70%; background: #6366f1; color: #fff; padding: 1rem 1.25rem; border-radius: 12px; font-weight: 500;';
  userDiv.textContent = msg;
  container.appendChild(userDiv);

  input.value = '';
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

    const aiDiv = document.createElement('div');
    aiDiv.style.cssText = 'align-self: flex-start; max-width: 70%; background: #1e1e2e; color: #cbd5e1; padding: 1rem 1.25rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.05);';
    aiDiv.textContent = data.reply || data.message || 'Error processing query.';
    container.appendChild(aiDiv);
    container.scrollTop = container.scrollHeight;
  } catch(err) {
    console.error(err);
  }
});
</script>
@endsection
@endsection
