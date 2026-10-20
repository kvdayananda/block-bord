<?php

return [
    'clamav' => [
        'host' => env('CLAMAV_HOST', '127.0.0.1'),
        'port' => (int) env('CLAMAV_PORT', 3310),
        'timeout' => (float) env('CLAMAV_TIMEOUT', 10),
    ],
    'qr_decoder' => [
        'binary' => env('QR_DECODER_BINARY', 'zbarimg'),
    ],
    'razorpay' => [
        'key' => env('RAZORPAY_KEY_ID', env('RAZORPAY_KEY', '')),
        'secret' => env('RAZORPAY_KEY_SECRET', env('RAZORPAY_SECRET', '')),
        'webhook_secret' => env('RAZORPAY_WEBHOOK_SECRET', ''),
    ],
];
