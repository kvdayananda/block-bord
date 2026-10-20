@extends('layouts.app')

@section('title', 'Security Alerts & Notifications — Block Bord AI')

@section('content')
<div style="display: flex; min-height: calc(100vh - 70px); background: #060814;">
  <x-sidebar />

  <main style="flex: 1; padding: 2.5rem; background: #060814; color: #fff;">

    <!-- Header Section -->
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2.5rem; flex-wrap: wrap; gap: 1rem;">
      <div>
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 6px;">
          <h1 style="font-size: 2.25rem; font-weight: 900; color: #fff; margin: 0;">Security Alerts & Feed</h1>
          @if($unreadCount > 0)
            <span style="background: rgba(239, 68, 68, 0.2); color: #ef4444; font-weight: 800; padding: 4px 12px; border-radius: 9999px; font-size: 0.8rem; border: 1px solid rgba(239,68,68,0.3);">
              {{ $unreadCount }} Unread
            </span>
          @endif
        </div>
        <p style="color: #94a3b8; font-size: 0.975rem;">Real-time threat alerts, account integrity updates, and perimeter intelligence notifications.</p>
      </div>

      @if($unreadCount > 0)
        <div>
          <form method="POST" action="{{ route('notifications.markAllRead') }}">
            @csrf
            <button type="submit" style="background: rgba(99, 102, 241, 0.15); color: #a5b4fc; border: 1px solid rgba(99, 102, 241, 0.35); padding: 0.75rem 1.25rem; border-radius: 10px; font-weight: 700; font-size: 0.875rem; cursor: pointer; transition: background 0.2s;" onmouseover="this.style.background='rgba(99,102,241,0.3)'" onmouseout="this.style.background='rgba(99,102,241,0.15)'">
              ✓ Mark All as Read
            </button>
          </form>
        </div>
      @endif
    </div>

    <!-- Filter Tabs -->
    <div style="display: flex; gap: 10px; margin-bottom: 2rem; flex-wrap: wrap;">
      @foreach(['all' => 'All Alerts', 'threat_alert' => '🛡️ Threat Interceptions', 'warning' => '⚠️ Warnings', 'info' => 'ℹ️ System Updates', 'payment' => '💳 Billing'] as $key => $label)
        <a href="{{ route('notifications.index', ['type' => $key]) }}" style="padding: 0.6rem 1.2rem; border-radius: 10px; font-size: 0.875rem; font-weight: 700; text-decoration: none; transition: all 0.2s; background: {{ ($currentType ?? 'all') === $key ? 'rgba(99, 102, 241, 0.25)' : 'rgba(15, 23, 42, 0.8)' }}; color: {{ ($currentType ?? 'all') === $key ? '#a5b4fc' : '#94a3b8' }}; border: 1px solid {{ ($currentType ?? 'all') === $key ? 'rgba(99, 102, 241, 0.5)' : 'rgba(255,255,255,0.08)' }};">
          {{ $label }}
        </a>
      @endforeach
    </div>

    <!-- Notifications List -->
    @if($notifications->isEmpty())
      <div style="background: rgba(15, 23, 42, 0.6); border: 1px dashed rgba(99, 102, 241, 0.3); border-radius: 20px; padding: 4rem 2rem; text-align: center;">
        <div style="font-size: 3rem; margin-bottom: 1rem;">🔔</div>
        <h3 style="font-size: 1.35rem; font-weight: 800; color: #fff; margin-bottom: 0.5rem;">All clear! No alerts in this category</h3>
        <p style="color: #94a3b8; font-size: 0.95rem; max-width: 480px; margin: 0 auto;">
          Your threat monitoring system is active. New security alerts and system events will appear here in real-time.
        </p>
      </div>
    @else
      <div style="display: flex; flex-direction: column; gap: 1rem; margin-bottom: 2rem;">
        @foreach($notifications as $notif)
          @php
            $isThreat = $notif->type === 'threat_alert';
            $isWarning = $notif->type === 'warning';
            $isPayment = $notif->type === 'payment';
            $icon = $isThreat ? '🛡️' : ($isWarning ? '⚠️' : ($isPayment ? '💳' : 'ℹ️'));
            $accentColor = $isThreat ? '#ef4444' : ($isWarning ? '#f59e0b' : ($isPayment ? '#10b981' : '#6366f1'));
            $accentBg = $isThreat ? 'rgba(239, 68, 68, 0.15)' : ($isWarning ? 'rgba(245, 158, 11, 0.15)' : ($isPayment ? 'rgba(16, 185, 129, 0.15)' : 'rgba(99, 102, 241, 0.15)'));
          @endphp

          <div style="background: {{ $notif->is_read ? 'rgba(15, 23, 42, 0.6)' : 'rgba(15, 23, 42, 0.9)' }}; backdrop-filter: blur(16px); border: 1px solid {{ $notif->is_read ? 'rgba(255,255,255,0.06)' : 'rgba(99, 102, 241, 0.35)' }}; border-radius: 16px; padding: 1.5rem 1.75rem; display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 1.25rem; transition: border-color 0.2s;">

            <div style="display: flex; align-items: flex-start; gap: 16px; flex: 1; min-width: 280px;">
              <div style="width: 42px; height: 42px; border-radius: 12px; background: {{ $accentBg }}; color: {{ $accentColor }}; display: flex; align-items: center; justify-content: center; font-size: 1.25rem; flex-shrink: 0; margin-top: 2px;">
                {{ $icon }}
              </div>

              <div>
                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 6px;">
                  <h4 style="font-size: 1.1rem; font-weight: 800; color: #fff; margin: 0;">
                    {{ $notif->title }}
                  </h4>
                  @if(!$notif->is_read)
                    <span style="width: 8px; height: 8px; border-radius: 50%; background: #6366f1; display: inline-block;"></span>
                  @endif
                </div>
                <p style="color: #cbd5e1; font-size: 0.925rem; margin: 0 0 8px 0; line-height: 1.5;">
                  {{ $notif->message }}
                </p>
                <span style="color: #64748b; font-size: 0.8rem;">
                  {{ $notif->created_at->diffForHumans() }}
                </span>
              </div>
            </div>

            <div style="display: flex; gap: 8px; align-items: center;">
              @if(!$notif->is_read)
                <form method="POST" action="{{ route('notifications.read', $notif->id) }}" style="display: inline;">
                  @csrf
                  <button type="submit" title="Mark as read" style="background: rgba(255,255,255,0.06); color: #a5b4fc; border: 1px solid rgba(255,255,255,0.1); padding: 6px 12px; border-radius: 8px; font-size: 0.8rem; font-weight: 600; cursor: pointer;">
                    Mark Read
                  </button>
                </form>
              @endif

              <form method="POST" action="{{ route('notifications.delete', $notif->id) }}" style="display: inline;">
                @csrf
                @method('DELETE')
                <button type="submit" title="Dismiss notification" style="background: transparent; color: #64748b; border: none; padding: 6px 10px; border-radius: 8px; font-size: 0.85rem; cursor: pointer;" onmouseover="this.style.color='#ef4444'" onmouseout="this.style.color='#64748b'">
                  ✕
                </button>
              </form>
            </div>

          </div>
        @endforeach
      </div>

      <!-- Pagination -->
      <div>
        {{ $notifications->links() }}
      </div>
    @endif

  </main>
</div>
@endsection
