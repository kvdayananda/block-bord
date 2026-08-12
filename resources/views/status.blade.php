@extends('layouts.app')
@section('title', 'System Status — Block Bord AI')
@section('content')
<section style="padding: 4rem 1.5rem; max-width: 800px; margin: 0 auto; color: #cbd5e1;">
  <h1 style="color: #fff; font-size: 2.5rem; font-weight: 800; margin-bottom: 1.5rem; text-align: center;">System Status</h1>
  <div style="background: #1e1e2e; padding: 2rem; border-radius: 14px; border: 1px solid rgba(255,255,255,0.08);">
    <div style="display: flex; justify-content: space-between; padding: 1rem 0; border-bottom: 1px solid #33334d;">
      <span>Laravel Web Core</span>
      <span style="color: #10b981; font-weight: 700;">🟢 Operational</span>
    </div>
    <div style="display: flex; justify-content: space-between; padding: 1rem 0; border-bottom: 1px solid #33334d;">
      <span>MySQL Database Engine</span>
      <span style="color: #10b981; font-weight: 700;">🟢 Operational</span>
    </div>
    <div style="display: flex; justify-content: space-between; padding: 1rem 0; border-bottom: 1px solid #33334d;">
      <span>Python ML Microservice (Port 8001)</span>
      <span style="color: #10b981; font-weight: 700;">🟢 Operational</span>
    </div>
    <div style="display: flex; justify-content: space-between; padding: 1rem 0;">
      <span>AI Fallback Engine (Gemini / OpenAI)</span>
      <span style="color: #10b981; font-weight: 700;">🟢 Operational</span>
    </div>
  </div>
</section>
@endsection
