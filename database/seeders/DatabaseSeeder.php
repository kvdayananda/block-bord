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
        // Seed default admin user if not exists
        User::firstOrCreate(
            ['email' => 'admin@blockbord.ai'],
            [
                'username' => 'admin',
                'password' => Hash::make('AdminPass123!'),
                'is_admin' => true,
                'is_pro' => true,
                'plan' => 'pro',
                'is_active' => true,
                'is_email_verified' => true,
                'api_key' => 'bb_live_' . Str::random(32),
            ]
        );

        // Seed default demo user if not exists
        User::firstOrCreate(
            ['email' => 'user@blockbord.ai'],
            [
                'username' => 'demouser',
                'password' => Hash::make('UserPass123!'),
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
