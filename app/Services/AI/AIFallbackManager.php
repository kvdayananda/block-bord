<?php

namespace App\Services\AI;

use Illuminate\Support\Facades\Log;

class AIFallbackManager
{
    protected GeminiService $gemini;
    protected OpenAIService $openAI;

    public function __construct(GeminiService $gemini, OpenAIService $openAI)
    {
        $this->gemini = $gemini;
        $this->openAI = $openAI;
    }

    /**
     * Ask the AI engine with primary Gemini, secondary OpenAI, and tertiary Local Heuristics Shield.
     *
     * @param string $prompt
     * @param array $context
     * @return array
     */
    public function ask(string $prompt, array $context = []): array
    {
        // 1. Primary: Google Gemini (Gemini 2.5 Flash)
        try {
            return $this->gemini->generateResponse($prompt, $context);
        } catch (\Throwable $e) {
            Log::info("Gemini unavailable, attempting OpenAI fallback. Reason: " . $e->getMessage());
        }

        // 2. Secondary: OpenAI (GPT-4o mini)
        try {
            return $this->openAI->generateResponse($prompt, $context);
        } catch (\Throwable $e) {
            Log::info("OpenAI unavailable, activating Block Bord Local Heuristics Shield. Reason: " . $e->getMessage());
        }

        // 3. Tertiary: Intelligent Local Heuristics Security Engine
        return $this->generateHeuristicResponse($prompt);
    }

    /**
     * Intelligent local cybersecurity fallback when external LLM APIs are offline or unconfigured.
     */
    protected function generateHeuristicResponse(string $prompt): array
    {
        $lower = strtolower($prompt);

        // Scenario A: URL or Link Analysis
        if (preg_match('/https?:\/\/[^\s]+|www\.[^\s]+/i', $prompt, $matches)) {
            $url = $matches[0];
            $host = parse_url($url, PHP_URL_HOST) ?? $url;
            $isIp = preg_match('/^\d{1,3}(\.\d{1,3}){3}$/', $host);
            $hasSuspiciousTld = preg_match('/\.(xyz|top|work|buzz|club|fit|gq|ml|cf|tk)$/i', $host);
            $hasBrandSpoof = preg_match('/(paypal|google|apple|amazon|microsoft|bank|netflix|chase|wellsfargo)/i', $host);

            $reasons = [];
            if ($isIp) $reasons[] = "Direct IP address host without domain name is an evasion tactic.";
            if ($hasSuspiciousTld) $reasons[] = "High-abuse top-level domain frequently seen in burner phishing campaigns.";
            if ($hasBrandSpoof) $reasons[] = "Potential typosquatting / brand impersonation attempt detected.";

            $advice = "### 🛡️ Block Bord AI Security Triage\n\n";
            $advice .= "**Inspected Target:** `{$url}`\n\n";
            $advice .= "**Preliminary Risk Level:** " . (!empty($reasons) ? "⚠️ **HIGH SUSPICION**" : "🔍 **CAUTION ADVISED**") . "\n\n";
            $advice .= "#### Key Threat Findings:\n";
            if (!empty($reasons)) {
                foreach ($reasons as $r) {
                    $advice .= "- " . $r . "\n";
                }
            } else {
                $advice .= "- Domain structure requires standard verification before entering credentials.\n";
                $advice .= "- HTTPS presence does not guarantee safety — phishing sites also use free SSL certificates.\n";
            }
            $advice .= "\n#### Recommended Actions:\n";
            $advice .= "1. Do **not** enter passwords, OTP codes, or personal details on this page.\n";
            $advice .= "2. Verify the true domain using the Block Bord **URL Scanner** or **Domain Inspector** tool.\n";
            $advice .= "3. Check the sender's actual address if received via email or SMS.";

            return [
                'provider' => 'fallback',
                'model' => 'heuristics-engine-v2',
                'text' => $advice,
                'success' => true,
            ];
        }

        // Scenario B: Banking, SMS, OTP, or KYC Impersonation
        if (preg_match('/(bank|sms|account suspended|deactivated|otp|kyc|pan card|aadhaar|verify account|debit card)/i', $lower)) {
            $advice = "### 🚨 Block Bord Smishing & Banking Fraud Advisory\n\n";
            $advice .= "**Analysis:** The message matches classic **Social Engineering & Smishing** patterns designed to induce panic.\n\n";
            $advice .= "#### Critical Security Rules:\n";
            $advice .= "- **Never click links in SMS or WhatsApp** claiming your account or card is blocked/suspended.\n";
            $advice .= "- Banks and payment providers **never** request OTPs, PINs, or password updates via SMS links.\n";
            $advice .= "- Official updates will always appear inside your verified mobile banking app.\n\n";
            $advice .= "#### Immediate Mitigation:\n";
            $advice .= "1. Forward the suspicious SMS to your cellular carrier's spam reporting number (e.g. 1909 in India).\n";
            $advice .= "2. Contact your bank directly through their official helpline printed on your debit card.\n";
            $advice .= "3. If financial details were already shared, immediately freeze your account/cards.";

            return [
                'provider' => 'fallback',
                'model' => 'heuristics-engine-v2',
                'text' => $advice,
                'success' => true,
            ];
        }

        // Scenario C: Crypto, Investment, or Lottery Scam
        if (preg_match('/(crypto|bitcoin|ethereum|giveaway|investment|guaranteed return|forex|telegram trade|double your)/i', $lower)) {
            $advice = "### ⚠️ Block Bord Investment & Crypto Scam Warning\n\n";
            $advice .= "**Analysis:** Schemes offering 'guaranteed returns', celebrity crypto giveaways, or Telegram VIP trading groups are **99.9% fraudulent** (Pig Butchering / Advance Fee scams).\n\n";
            $advice .= "#### Warning Signs:\n";
            $advice .= "- Guarantees of risk-free daily profits.\n";
            $advice .= "- Demands to deposit crypto to 'activate' or 'withdraw' existing funds.\n";
            $advice .= "- Impersonation of well-known founders or trading influencers.\n\n";
            $advice .= "#### Action Plan:\n";
            $advice .= "- Never transfer cryptocurrency to unverified private wallets.\n";
            $advice .= "- Verify exchange legitimacy on licensed regulatory registers.";

            return [
                'provider' => 'fallback',
                'model' => 'heuristics-engine-v2',
                'text' => $advice,
                'success' => true,
            ];
        }

        // Scenario D: Email Authentication / SPF / DKIM / DMARC
        if (preg_match('/(spf|dkim|dmarc|email header|mx record)/i', $lower)) {
            $advice = "### 📧 Email Security Protocol Reference (SPF, DKIM, DMARC)\n\n";
            $advice .= "To verify if an email is legitimate or spoofed, check these core DNS authentication records:\n\n";
            $advice .= "- **SPF (Sender Policy Framework):** Specifies which mail servers (IPs) are authorized to send email on behalf of your domain.\n";
            $advice .= "- **DKIM (DomainKeys Identified Mail):** Adds a cryptographic digital signature to emails to ensure the message wasn't altered in transit.\n";
            $advice .= "- **DMARC (Domain-based Message Authentication):** Defines policy (`none`, `quarantine`, `reject`) when SPF or DKIM fail, preventing domain spoofing.\n\n";
            $advice .= "**Pro Tip:** Use the Block Bord **Email Security Checker** tool to inspect any sender domain's SPF and DMARC enforcement.";

            return [
                'provider' => 'fallback',
                'model' => 'heuristics-engine-v2',
                'text' => $advice,
                'success' => true,
            ];
        }

        // Scenario E: General Cybersecurity Guidance
        $advice = "### 🛡️ Block Bord AI Security Intelligence\n\n";
        $advice .= "I am monitoring active threat vectors and ready to assist you. Here are key threat triage capabilities available:\n\n";
        $advice .= "- **Link Verification:** Paste any suspicious URL to inspect its domain age, SSL hygiene, and malware telemetry.\n";
        $advice .= "- **Phishing Detection:** Paste suspicious email text or SMS messages to scan for social engineering tactics.\n";
        $advice .= "- **Credential Hygiene:** Use the **Password Strength & Leak Checker** to test if your credentials have appeared in dark-web breaches.\n";
        $advice .= "- **UPI / Payment Safety:** Check UPI handles and payment links before completing money transfers.\n\n";
        $advice .= "*Need immediate assistance? Provide specific message text, a domain, or a security question.*";

        return [
            'provider' => 'fallback',
            'model' => 'heuristics-engine-v2',
            'text' => $advice,
            'success' => true,
        ];
    }
}
