@extends('layouts.app')

@section('title', 'Payment & Subscription Ledger — Admin Console — Block Bord AI')

@section('content')
<div style="display: flex; min-height: calc(100vh - 70px); background: #060814;">
  <x-sidebar />

  <main style="flex: 1; padding: 2.5rem; background: #060814; color: #fff;">

    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; flex-wrap: wrap; gap: 1rem;">
      <div>
        <h1 style="font-size: 2.25rem; font-weight: 900; color: #fff; margin: 0 0 4px 0;">Payment & Revenue Ledger</h1>
        <p style="color: #94a3b8; font-size: 0.95rem; margin: 0;">Monitor Razorpay transactions, subscription activations, and financial settlements.</p>
      </div>
    </div>

    <!-- Admin Nav Tabs -->
    <x-admin-nav />

    <!-- Revenue Metric Cards -->
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1.5rem; margin-bottom: 2.5rem;">

      <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(217, 70, 239, 0.25); border-radius: 18px; padding: 1.75rem;">
        <div style="color: #94a3b8; font-size: 0.85rem; font-weight: 600; margin-bottom: 4px;">Total Captured Revenue</div>
        <div style="font-size: 2.25rem; font-weight: 900; color: #f472b6;">${{ number_format($totalRevenue, 2) }}</div>
        <div style="font-size: 0.8rem; color: #10b981; margin-top: 4px; font-weight: 600;">{{ $capturedCount }} successful payments</div>
      </div>

      <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(245, 158, 11, 0.25); border-radius: 18px; padding: 1.75rem;">
        <div style="color: #94a3b8; font-size: 0.85rem; font-weight: 600; margin-bottom: 4px;">Pending Orders</div>
        <div style="font-size: 2.25rem; font-weight: 900; color: #f59e0b;">{{ $pendingCount }}</div>
        <div style="font-size: 0.8rem; color: #94a3b8; margin-top: 4px;">In checkout flow</div>
      </div>

      <div style="background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(239, 68, 68, 0.25); border-radius: 18px; padding: 1.75rem;">
        <div style="color: #94a3b8; font-size: 0.85rem; font-weight: 600; margin-bottom: 4px;">Failed Attempts</div>
        <div style="font-size: 2.25rem; font-weight: 900; color: #ef4444;">{{ $failedCount }}</div>
        <div style="font-size: 0.8rem; color: #ef4444; margin-top: 4px;">Declined / Expired</div>
      </div>

    </div>

    <!-- Payments Table -->
    <div style="background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(20px); border-radius: 20px; border: 1px solid rgba(99, 102, 241, 0.2); padding: 1.5rem; box-shadow: 0 12px 32px rgba(0,0,0,0.5);">
      <h3 style="font-size: 1.2rem; font-weight: 800; color: #fff; margin-bottom: 1rem;">
        Recent Transactions
      </h3>

      @if($payments->isEmpty())
        <div style="text-align: center; padding: 3rem 1rem; color: #94a3b8;">
          No transactions recorded yet.
        </div>
      @else
        <div style="overflow-x: auto;">
          <table style="width: 100%; border-collapse: collapse; text-align: left; color: #cbd5e1;">
            <thead>
              <tr style="border-bottom: 1px solid rgba(99, 102, 241, 0.2); color: #94a3b8; font-size: 0.825rem; text-transform: uppercase;">
                <th style="padding: 1rem;">Payment ID</th>
                <th style="padding: 1rem;">Customer</th>
                <th style="padding: 1rem;">Tier Plan</th>
                <th style="padding: 1rem;">Amount</th>
                <th style="padding: 1rem;">Status</th>
                <th style="padding: 1rem;">Order ID</th>
                <th style="padding: 1rem; text-align: right;">Date</th>
              </tr>
            </thead>
            <tbody>
              @foreach($payments as $pay)
                <tr style="border-bottom: 1px solid rgba(255,255,255,0.05); transition: background 0.2s;" onmouseover="this.style.background='rgba(99,102,241,0.08)'" onmouseout="this.style.background='transparent'">
                  <td style="padding: 1rem; font-family: var(--font-mono, monospace); color: #a5b4fc; font-weight: 700;">
                    {{ $pay->razorpay_payment_id ?: 'order_' . substr($pay->razorpay_order_id, -8) }}
                  </td>
                  <td style="padding: 1rem;">
                    <div style="font-weight: 700; color: #fff;">{{ $pay->user ? $pay->user->username : 'Guest' }}</div>
                    <div style="color: #64748b; font-size: 0.8rem;">{{ $pay->user ? $pay->user->email : 'N/A' }}</div>
                  </td>
                  <td style="padding: 1rem;">
                    <span style="text-transform: uppercase; font-weight: 800; font-size: 0.8rem; color: #f472b6;">
                      {{ $pay->plan }}
                    </span>
                  </td>
                  <td style="padding: 1rem; font-weight: 800; color: #fff;">
                    ${{ number_format($pay->amount, 2) }} {{ strtoupper($pay->currency ?? 'USD') }}
                  </td>
                  <td style="padding: 1rem;">
                    <span style="padding: 0.3rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 800; text-transform: uppercase; background: {{ $pay->status === 'captured' ? 'rgba(16, 185, 129, 0.15)' : ($pay->status === 'pending' ? 'rgba(245, 158, 11, 0.15)' : 'rgba(239, 68, 68, 0.15)') }}; color: {{ $pay->status === 'captured' ? '#10b981' : ($pay->status === 'pending' ? '#f59e0b' : '#ef4444') }}; border: 1px solid {{ $pay->status === 'captured' ? 'rgba(16, 185, 129, 0.3)' : ($pay->status === 'pending' ? 'rgba(245, 158, 11, 0.3)' : 'rgba(239, 68, 68, 0.3)') }};">
                      {{ $pay->status }}
                    </span>
                  </td>
                  <td style="padding: 1rem; font-family: var(--font-mono, monospace); font-size: 0.8rem; color: #64748b;">
                    {{ $pay->razorpay_order_id }}
                  </td>
                  <td style="padding: 1rem; color: #64748b; font-size: 0.825rem; text-align: right;">
                    {{ $pay->created_at->format('M d, Y H:i') }}
                  </td>
                </tr>
              @endforeach
            </tbody>
          </table>
        </div>

        <div style="margin-top: 1.5rem;">
          {{ $payments->links() }}
        </div>
      @endif
    </div>

  </main>
</div>
@endsection
