<?php

namespace App\Services\AI;

interface AIServiceInterface
{
    public function generateResponse(string $prompt, array $context = []): array;
}
