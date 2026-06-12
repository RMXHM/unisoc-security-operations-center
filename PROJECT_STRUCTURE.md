# Project Structure

## Overview

UniSOC follows a Laravel backend structure with a static dashboard frontend currently served through Laravel routes. The backend owns authentication, authorization, security log APIs, containment actions, rate limiting, and audit records.

## Major Folders

- `app/`: Laravel application code, including controllers, middleware, models, service classes, and providers.
- `app/Http/Controllers/`: API endpoints for authentication, security logs, dashboard summaries, and SOC actions.
- `app/Http/Middleware/`: SOC access control, CSRF enforcement, and security response headers.
- `app/Models/`: Eloquent models for users, security logs, blocked IPs, banned users, and action audits.
- `app/Services/`: Business logic for SOC metrics and environment-backed administrator account setup.
- `bootstrap/`: Laravel bootstrapping files and cache placeholder directory.
- `config/`: Laravel configuration for app, auth, cache, database, filesystems, logging, mail, queue, services, session, and CORS.
- `database/`: Migrations, seeders, and factories for local development and test data.
- `public/`: Public web entry point and static public assets managed by Laravel.
- `resources/`: Default Laravel frontend resource area for Vite-managed assets and Blade views.
- `routes/`: Web, API, and console route definitions.
- `storage/`: Runtime-only Laravel storage directories kept by placeholder files.
- `tests/`: PHPUnit feature and unit tests.

## Backend Components

- `AuthControllerR1`: Provides session bootstrap, SOC administrator login, and logout.
- `SecurityLogController`: Lists security logs with filters and active containment state.
- `SocDashboardControllerR1`: Returns dashboard summary data.
- `SocActionControllerR1`: Applies analyst actions and writes audit records.
- `SocAdminAccountServiceR1`: Reads SOC administrator identity from environment variables and creates the admin user.
- `SocDashboardMetricsServiceR1`: Computes dashboard metrics, anomalies, timelines, attacker summaries, and recent actions.

## Database

- `users`: Laravel user accounts used for the SOC administrator session.
- `security_logs`: Demonstration SOC event stream with user, event, IP, risk, status, and timestamp fields.
- `blocked_ips_r1`: Active and historical IP containment records.
- `banned_users_r1`: Active user containment records.
- `soc_action_audits_r1`: Immutable-style audit records for analyst actions.
- `cache`, `jobs`, `sessions`: Laravel framework tables for local runtime support.

## Security Modules

- Environment-based SOC admin credentials through `SOC_ADMIN_NAME`, `SOC_ADMIN_EMAIL`, and `SOC_ADMIN_PASSWORD`.
- `EnsureSocAdminR1` protects dashboard and authenticated API routes.
- `EnforceCsrfTokenR1` requires `X-CSRF-TOKEN` for mutating API requests.
- `SocApiSecurityHeaders` sets no-cache headers, CSP, frame protection, content-type protection, referrer policy, and permissions policy.
- Rate limiters separate general SOC API traffic, authentication attempts, and analyst actions.

## Frontend Components

- `loginR1.html`: SOC login screen.
- `index.html`: Main SOC dashboard shell.
- `style.css`: Dashboard and login styling.
- `authR1.js`: Login/session client logic.
- `script.js`: Dashboard API integration and UI behavior.
- `chartR1.js`: Bundled Chart.js library.
- `logo.png`: University/SOC visual asset.

## Recommended Future Structure

- Move static dashboard assets from the project root into `resources/` with Vite or into `public/` as intentional public assets.
- Remove the default Laravel welcome view if it remains unused.
- Rename `R1` suffixed classes and files once the prototype revision label is no longer useful.
- Add a license file before publishing as an open-source repository.
