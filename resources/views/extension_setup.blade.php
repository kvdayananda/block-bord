@extends('layouts.app')
@section('title', 'Chrome Extension Setup — Block Bord AI')
@section('content')
<div style="display: flex; min-height: calc(100vh - 70px);">
  <x-sidebar />
  <main style="flex: 1; padding: 2.5rem; background: #0f0f17; color: #fff;">
    <h1 style="font-size: 2rem; font-weight: 800; margin-bottom: 1.5rem;">🧩 Chrome Extension Setup</h1>
    <div style="background: #1e1e2e; padding: 2rem; border-radius: 12px; border: 1px solid rgba(255,255,255,0.08); max-width: 750px; line-height: 1.8;">
      <h3 style="color: #6366f1; margin-bottom: 1rem;">Install Block Bord AI Extension</h3>
      <ol style="color: #cbd5e1; padding-left: 1.25rem;">
        <li>Open Chrome and navigate to <code>chrome://extensions</code>.</li>
        <li>Enable <strong>Developer mode</strong> in the top-right corner.</li>
        <li>Click <strong>Load unpacked</strong> and select the <code>extension</code> directory from this project.</li>
        <li>Click the extension icon in your browser toolbar to connect to your Block Bord account!</li>
      </ol>
    </div>
  </main>
</div>
@endsection
