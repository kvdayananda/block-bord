@extends('layouts.app')

@section('title', 'Contact Us — Block Bord AI')

@section('content')
<section style="padding: 4rem 1.5rem; max-width: 700px; margin: 0 auto; color: #cbd5e1;">
  <h1 style="font-size: 2.5rem; font-weight: 900; color: #fff; text-align: center; margin-bottom: 1rem;">Contact Support</h1>
  <p style="text-align: center; color: #94a3b8; margin-bottom: 2.5rem;">Have questions or security inquiries? Send us a message.</p>

  <form style="background: #1e1e2e; padding: 2rem; border-radius: 14px; border: 1px solid rgba(255,255,255,0.08);">
    <div style="margin-bottom: 1.25rem;">
      <label style="display: block; margin-bottom: 0.5rem; color: #fff; font-size: 0.9rem;">Your Name</label>
      <input type="text" placeholder="John Doe" style="width: 100%; padding: 0.75rem 1rem; border-radius: 8px; border: 1px solid #33334d; background: #11111b; color: #fff;">
    </div>
    <div style="margin-bottom: 1.25rem;">
      <label style="display: block; margin-bottom: 0.5rem; color: #fff; font-size: 0.9rem;">Email Address</label>
      <input type="email" placeholder="john@example.com" style="width: 100%; padding: 0.75rem 1rem; border-radius: 8px; border: 1px solid #33334d; background: #11111b; color: #fff;">
    </div>
    <div style="margin-bottom: 1.5rem;">
      <label style="display: block; margin-bottom: 0.5rem; color: #fff; font-size: 0.9rem;">Message</label>
      <textarea rows="5" placeholder="How can we help you?" style="width: 100%; padding: 0.75rem 1rem; border-radius: 8px; border: 1px solid #33334d; background: #11111b; color: #fff;"></textarea>
    </div>
    <button type="submit" style="width: 100%; padding: 0.85rem; background: #6366f1; color: #fff; font-weight: 700; border: none; border-radius: 8px; cursor: pointer;">Send Message</button>
  </form>
</section>
@endsection
