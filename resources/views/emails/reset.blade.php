<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Reset Password — Block Bord AI</title>
</head>
<body style="font-family: Arial, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 40px;">
    <div style="max-width: 500px; margin: 0 auto; background-color: #1e293b; padding: 30px; border-radius: 12px; border: 1px solid #334155;">
        <h2 style="color: #3b82f6; margin-top: 0;">🔐 Block Bord AI</h2>
        <p>Hello <strong>{{ $user->username }}</strong>,</p>
        <p>You requested a password reset for your Block Bord AI account. Click the button below to reset your password:</p>
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{ $resetUrl }}" style="background-color: #2563eb; color: #ffffff; padding: 12px 24px; text-decoration: none; border-radius: 8px; font-weight: bold; display: inline-block;">Reset Password</a>
        </div>
        <p style="font-size: 12px; color: #94a3b8;">This reset link will expire in 2 hours. If you did not request a password reset, please ignore this message.</p>
    </div>
</body>
</html>
