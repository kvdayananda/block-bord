<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class PublicController extends Controller
{
    public function landing()
    {
        return view('landing');
    }

    public function features()
    {
        return view('features');
    }

    public function pricing()
    {
        return view('pricing');
    }

    public function about()
    {
        return view('about');
    }

    public function contact()
    {
        return view('contact');
    }

    public function privacy()
    {
        return view('privacy');
    }

    public function terms()
    {
        return view('terms');
    }

    public function cookie()
    {
        return view('cookie');
    }

    public function securityPolicy()
    {
        return view('security_policy');
    }

    public function responsibleDisclosure()
    {
        return view('responsible_disclosure');
    }

    public function faq()
    {
        return view('faq');
    }

    public function status()
    {
        return view('status');
    }

    public function sitemap()
    {
        $urls = [
            route('landing'),
            route('features'),
            route('pricing'),
            route('about'),
            route('contact'),
            route('privacy'),
            route('terms'),
            route('cookie'),
            route('security.policy'),
            route('responsible.disclosure'),
            route('faq'),
            route('status'),
            route('tools.home'),
            route('ai.page'),
        ];

        $xml = '<?xml version="1.0" encoding="UTF-8"?>';
        $xml .= '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">';
        foreach ($urls as $url) {
            $xml .= '<url><loc>' . htmlspecialchars($url) . '</loc><changefreq>weekly</changefreq><priority>0.8</priority></url>';
        }
        $xml .= '</urlset>';

        return response($xml, 200, ['Content-Type' => 'application/xml']);
    }
}
