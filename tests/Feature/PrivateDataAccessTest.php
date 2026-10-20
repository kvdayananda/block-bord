<?php

namespace Tests\Feature;

use Tests\TestCase;

class PrivateDataAccessTest extends TestCase
{
    public function test_guests_cannot_list_or_retrieve_scan_data(): void
    {
        $this->getJson('/api/v1/scans')->assertUnauthorized();
        $this->getJson('/api/v1/scans/1')->assertUnauthorized();
        $this->getJson('/api/v1/reports/1')->assertUnauthorized();
    }

    public function test_guests_cannot_access_saved_ai_conversations(): void
    {
        $this->postJson('/api/v1/ai/chat', ['message' => 'Is this link safe?'])
            ->assertUnauthorized();
        $this->get('/ai')->assertRedirect('/login');
        $this->get('/ai/conversation/1')->assertRedirect('/login');
        $this->delete('/ai/conversation/1')->assertRedirect('/login');
    }

    public function test_scanner_endpoints_do_not_accept_missing_uploads(): void
    {
        $this->postJson('/api/v1/scan/qr')->assertStatus(422);
        $this->postJson('/api/v1/scan/file')->assertStatus(422);
    }
}
