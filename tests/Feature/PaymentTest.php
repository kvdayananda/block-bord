<?php

namespace Tests\Feature;

use Tests\TestCase;

class PaymentTest extends TestCase
{
    public function test_pricing_page_renders_successfully(): void
    {
        $response = $this->get('/pricing');
        $response->assertStatus(200);
    }

    public function test_unauthenticated_user_cannot_create_order(): void
    {
        $response = $this->postJson('/payments/create-order', ['plan' => 'pro']);
        $response->assertStatus(401);
    }
}
