@extends('layouts.app')

@section('title', 'About Us — Block Bord AI')

@section('content')
<section style="padding: 4rem 1.5rem; max-width: 900px; margin: 0 auto; color: #cbd5e1; line-height: 1.8;">
  <h1 style="font-size: 2.75rem; font-weight: 900; color: #fff; margin-bottom: 1.5rem;">About Block Bord AI</h1>
  <p style="font-size: 1.15rem; margin-bottom: 1.5rem;">
    Block Bord AI is an enterprise-grade AI cybersecurity intelligence platform engineered to protect users and businesses from real-time online threats, phishing scams, and malicious URLs.
  </p>
  <p style="font-size: 1.05rem; margin-bottom: 1.5rem;">
    Our architecture pairs high-performance machine learning models (XGBoost) with multi-engine LLM Fallbacks (Gemini and OpenAI) to analyze URLs, IP addresses, SSL certificates, payment VPAs, and email data within milliseconds.
  </p>
</section>
@endsection
