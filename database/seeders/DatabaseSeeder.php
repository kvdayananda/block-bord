<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Str;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     *
     * @return void
     */
    public function run()
    {
        if (app()->environment('production')) {
            return;
        }

        $adminPassword = env('SEED_ADMIN_PASSWORD');
        if ($adminPassword) {
            User::firstOrCreate(
                ['email' => 'admin@blockbord.ai'],
                [
                    'username' => 'admin',
                    'password' => Hash::make($adminPassword),
                    'is_admin' => true,
                    'is_pro' => true,
                    'plan' => 'pro',
                    'is_active' => true,
                    'is_email_verified' => true,
                    'api_key' => 'bb_live_' . Str::random(32),
                ]
            );
        }

        $demoPassword = env('SEED_DEMO_PASSWORD');
        if ($demoPassword) {
            User::firstOrCreate(
                ['email' => 'user@blockbord.ai'],
                [
                    'username' => 'demouser',
                    'password' => Hash::make($demoPassword),
                    'is_admin' => false,
                    'is_pro' => false,
                    'plan' => 'free',
                    'is_active' => true,
                    'is_email_verified' => true,
                    'api_key' => 'bb_live_' . Str::random(32),
                ]
            );
        }
    }
}
