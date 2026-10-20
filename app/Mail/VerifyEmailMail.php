<?php

namespace App\Mail;

use App\Models\User;
use Illuminate\Bus\Queueable;
use Illuminate\Mail\Mailable;
use Illuminate\Queue\SerializesModels;

class VerifyEmailMail extends Mailable
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
        return $this->subject('Verify Your Email — Block Bord AI')
                    ->view('emails.verify')
                    ->with([
                        'user' => $this->user,
                        'verifyUrl' => route('verification.verify', ['token' => $this->token]),
                    ]);
    }
}
