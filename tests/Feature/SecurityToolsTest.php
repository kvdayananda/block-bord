<?php

namespace Tests\Feature;

use Tests\TestCase;
use App\Services\Security\SecurityToolService;

class SecurityToolsTest extends TestCase
{
    public function test_url_scanner_detects_suspicious_keywords(): void
    {
        $service = new SecurityToolService();
        $result = $service->scanUrl('http://banking-verify-update-login.free-wallet.com');

        $this->assertGreaterThanOrEqual(70, $result['risk_score']);
        $this->assertEquals('high', $result['risk_level']);
    }

    public function test_password_checker_evaluates_pwned_prefix(): void
    {
        $service = new SecurityToolService();
        $result = $service->checkPassword('Password123!');

        $this->assertArrayHasKey('is_pwned', $result);
        $this->assertArrayHasKey('strength_rating', $result);
    }
}
