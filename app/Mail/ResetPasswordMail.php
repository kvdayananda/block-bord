<?php

namespace App\Mail;

use App\Models\User;
use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;

class ResetPasswordMail extends Mailable
{
    use Queueable, SerializesModels;

    public User $user;
    public string $token;

    public function __construct(User $user, string $token)
    {
        $this->user = $user;
        $this->token = $token;
    }

    public function build()
    {
        return $this->subject('Reset Your Password — Block Bord AI')
                    ->view('emails.reset')
                    ->with([
                        'user' => $this->user,
                        'resetUrl' => route('password.reset', ['token' => $this->token]),
                    ]);
    }
}
