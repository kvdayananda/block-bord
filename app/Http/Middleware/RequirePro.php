<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class RequirePro
{
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();
        if (!$user || (!$user->is_pro && $user->plan === 'free' && !$user->is_admin)) {
            if ($request->expectsJson()) {
                return response()->json(['success' => false, 'message' => 'Pro subscription required for this feature.'], 403);
            }
            return redirect()->route('pricing')->with('error', 'Pro subscription required.');
        }

        return $next($request);
    }
}
