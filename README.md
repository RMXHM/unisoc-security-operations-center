# UniSOC

UniSOC is a Laravel-based Security Operations Center (SOC) simulation platform designed to replicate real-world security monitoring and incident response workflows in a controlled university environment.

## Features

- Secure SOC administrator login backed by Laravel sessions and CSRF validation.
- Dashboard summary metrics for threats, login activity, blocked IPs, banned users, anomalies, and honeypot hits.
- Security log filtering by search term, IP address, user, event, risk, and status.
- Analyst actions for blocking IPs, unblocking IPs, banning users, marking logs suspicious, and deleting logs.
- SOC action audit trail for accountability.
- Security headers, content security policy, rate limiting, and server-side validation.
- SQLite-ready development setup with migrations and seed data.
- PHPUnit feature coverage for authentication, log APIs, and SOC actions.

## Security Architecture

UniSOC implements a layered security model including:

- Session-based authentication for SOC administrators
- CSRF protection for all state-changing operations
- Role-gated SOC dashboard access
- Rate limiting for authentication and analyst actions
- Security headers (CSP, X-Frame-Options, Referrer Policy)
- Server-side validation for all SOC operations
- Audit logging for all containment actions

## Technology Stack

- PHP 8.3
- Laravel 13
- SQLite by default, with Laravel database configuration support for other drivers
- Eloquent ORM and database migrations
- Laravel sessions, middleware, validation, rate limiting, and seeders
- PHPUnit 12
- HTML, CSS, and vanilla JavaScript
- Chart.js bundled for dashboard visualization
- Vite and Tailwind dependencies from the Laravel frontend toolchain

## Getting Started

### Requirements

- PHP 8.3 or newer
- Composer
- Node.js and npm
- SQLite extension enabled for PHP

### Installation

```bash
composer install
npm install
cp .env.example .env
php artisan key:generate
php artisan migrate --seed
php artisan serve
```

Open `http://127.0.0.1:8000/login`.

Before logging in, set secure local values in `.env`:

```env
SOC_ADMIN_NAME="Your Name"
SOC_ADMIN_EMAIL=your-admin@example.test
SOC_ADMIN_PASSWORD="Use-A-Strong-Local-Password"
```

## Testing

```bash
php artisan test
```

The test suite uses PHPUnit environment variables and an in-memory SQLite database, so it does not require real SOC credentials or a local database file.

## Project Notes

- `.env` and runtime data are intentionally excluded from Git.
- The application uses seeded demonstration security logs for portfolio and internship review scenarios.
- This project is intended for educational and portfolio demonstration purposes and does not operate as a production incident response system.

## License

This repository is prepared for portfolio publication. Add a license file before accepting external contributions.
