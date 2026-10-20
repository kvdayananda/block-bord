<?php

namespace Tests\Feature;

use Tests\TestCase;
use App\Services\Security\SecurityToolService;
use App\Services\Security\GoogleSafeBrowsingService;
use Illuminate\Support\Facades\Http;
use Mockery;

class SecurityToolsTest extends TestCase
{
    public function test_url_scanner_detects_suspicious_keywords(): void
    {
        $safeBrowsing = Mockery::mock(GoogleSafeBrowsingService::class);
        $safeBrowsing->shouldReceive('checkUrl')->once()->andReturn([
            'is_malicious' => false,
            'threat_types' => [],
            'status' => 'unconfigured',
        ]);
        $service = new SecurityToolService($safeBrowsing);
        $result = $service->scanUrl('http://banking-verify-update-login.free-wallet.com');

        $this->assertGreaterThanOrEqual(70, $result['risk_score']);
        $this->assertEquals('high', $result['risk_level']);
    }

    public function test_password_checker_evaluates_pwned_prefix(): void
    {
        Http::fake([
            'api.pwnedpasswords.com/*' => Http::response('', 200),
        ]);
        $service = app(SecurityToolService::class);
        $result = $service->checkPassword('Password123!');

        $this->assertArrayHasKey('is_pwned', $result);
        $this->assertArrayHasKey('strength_rating', $result);
    }
}
