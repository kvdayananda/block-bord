@extends('layouts.app')

@section('title', 'Global Blacklist — Admin Console — Block Bord AI')

@section('content')
<div style="display: flex; min-height: calc(100vh - 70px); background: #060814;">
  <x-sidebar />

  <main style="flex: 1; padding: 2.5rem; background: #060814; color: #fff;">
    
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; flex-wrap: wrap; gap: 1rem;">
      <div>
        <h1 style="font-size: 2.25rem; font-weight: 900; color: #fff; margin: 0 0 4px 0;">Global Blacklist Perimeter</h1>
        <p style="color: #94a3b8; font-size: 0.95rem; margin: 0;">Enforce platform-wide immediate blocks across the Universal Risk Engine.</p>
      </div>
    </div>

    <!-- Admin Nav Tabs -->
    <x-admin-nav />

    <!-- Add Domain Form -->
    <div style="background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(16px); padding: 1.75rem; border-radius: 18px; border: 1px solid rgba(239, 68, 68, 0.25); margin-bottom: 2.5rem; max-width: 650px;">
      <h3 style="font-size: 1.15rem; font-weight: 800; color: #fff; margin: 0 0 1rem 0; display: flex; align-items: center; gap: 8px;">
        <span>🚫</span> Add Domain to Global Blacklist
      </h3>
      <form action="{{ route('admin.blacklist.add') }}" method="POST">
        @csrf
        <div style="display: flex; flex-direction: column; gap: 12px;">
          <input type="text" name="domain" placeholder="malicious-phishing-domain.xyz" required style="width: 100%; padding: 0.75rem 1rem; border-radius: 10px; border: 1px solid rgba(255,255,255,0.12); background: #060814; color: #fff; font-size: 0.95rem; outline: none;">
          <input type="text" name="reason" placeholder="Reason (e.g. Credential Harvesting / Malware Host)" style="width: 100%; padding: 0.75rem 1rem; border-radius: 10px; border: 1px solid rgba(255,255,255,0.12); background: #060814; color: #fff; font-size: 0.95rem; outline: none;">
          <button type="submit" style="background: #ef4444; color: #fff; padding: 0.75rem 1.5rem; border: none; border-radius: 10px; font-weight: 800; font-size: 0.9rem; cursor: pointer; align-self: flex-start; box-shadow: 0 4px 15px rgba(239,68,68,0.3);">
            + Add to Global Blacklist
          </button>
        </div>
      </form>
    </div>

    <!-- Blacklist Domains Table -->
    <div style="background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(20px); border-radius: 20px; border: 1px solid rgba(99, 102, 241, 0.2); padding: 1.5rem; box-shadow: 0 12px 32px rgba(0,0,0,0.5);">
      <h3 style="font-size: 1.2rem; font-weight: 800; color: #fff; margin-bottom: 1rem;">
        Active Blacklisted Domains
      </h3>

      @if($domains->isEmpty())
        <div style="text-align: center; padding: 3rem 1rem; color: #94a3b8;">
          No domains in blacklist yet.
        </div>
      @else
        <div style="overflow-x: auto;">
          <table style="width: 100%; border-collapse: collapse; text-align: left; color: #cbd5e1;">
            <thead>
              <tr style="border-bottom: 1px solid rgba(99, 102, 241, 0.2); color: #94a3b8; font-size: 0.825rem; text-transform: uppercase;">
                <th style="padding: 1rem;">Domain Name</th>
                <th style="padding: 1rem;">Classification Reason</th>
                <th style="padding: 1rem;">Added By</th>
                <th style="padding: 1rem;">Timestamp</th>
                <th style="padding: 1rem; text-align: right;">Action</th>
              </tr>
            </thead>
            <tbody>
              @foreach($domains as $item)
                <tr style="border-bottom: 1px solid rgba(255,255,255,0.05); transition: background 0.2s;" onmouseover="this.style.background='rgba(239,68,68,0.05)'" onmouseout="this.style.background='transparent'">
                  <td style="padding: 1rem; font-weight: 700; color: #f87171; font-family: var(--font-mono, monospace);">
                    {{ $item->domain }}
                  </td>
                  <td style="padding: 1rem; color: #cbd5e1; font-size: 0.9rem;">
                    {{ $item->reason ?: 'Admin Flagged' }}
                  </td>
                  <td style="padding: 1rem; color: #94a3b8; font-size: 0.85rem;">
                    {{ $item->addedBy ? $item->addedBy->username : 'System Admin' }}
                  </td>
                  <td style="padding: 1rem; color: #64748b; font-size: 0.825rem;">
                    {{ $item->created_at ? $item->created_at->format('M d, Y') : 'N/A' }}
                  </td>
                  <td style="padding: 1rem; text-align: right;">
                    <form method="POST" action="{{ route('admin.blacklist.delete', $item->id) }}" onsubmit="return confirm('Remove domain from blacklist?');">
                      @csrf
                      @method('DELETE')
                      <button type="submit" style="background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); padding: 4px 10px; border-radius: 6px; font-size: 0.75rem; font-weight: 700; cursor: pointer;">
                        Remove
                      </button>
                    </form>
                  </td>
                </tr>
              @endforeach
            </tbody>
          </table>
        </div>

        <div style="margin-top: 1.5rem;">
          {{ $domains->links() }}
        </div>
      @endif
    </div>

  </main>
</div>
@endsection
