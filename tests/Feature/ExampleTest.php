<?php

namespace Tests\Feature;

use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class ExampleTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Guests should be redirected to the login screen before viewing the dashboard shell.
     */
    public function test_the_dashboard_route_redirects_guests_to_login(): void
    {
        $response = $this->get('/');

        $response
            ->assertRedirect('/login');
    }

    public function test_the_login_route_returns_a_successful_response(): void
    {
        $response = $this->get('/login');

        $response
            ->assertOk()
            ->assertHeader('content-type', 'text/html; charset=UTF-8');
    }

    public function test_root_assets_are_served_by_laravel(): void
    {
        $this->get('/style.css')->assertOk();
        $this->get('/script.js')->assertOk();
        $this->get('/authR1.js')->assertOk();
        $this->get('/chartR1.js')->assertOk();
        $this->get('/logo.png')->assertOk();
    }
}
