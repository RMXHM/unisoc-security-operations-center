# Security Policy

## Supported Version

This repository is a portfolio and educational prototype. Security fixes should target the latest public `main` branch unless a release policy is added later.

## Reporting a Vulnerability

If you discover a vulnerability, do not open a public issue with exploit details. Contact the repository owner privately with:

- Affected endpoint or file
- Steps to reproduce
- Impact summary
- Suggested fix, if known

## Secret Handling

- Never commit `.env`, local database files, logs, cache files, session files, or generated framework artifacts.
- Configure the SOC administrator through environment variables:
  - `SOC_ADMIN_NAME`
  - `SOC_ADMIN_EMAIL`
  - `SOC_ADMIN_PASSWORD`
- Use a unique strong password for every local or deployed environment.
- Rotate credentials immediately if they were ever committed or shared publicly.

## Public Release Checklist

- Confirm `APP_DEBUG=false` before deployment.
- Set a fresh `APP_KEY` per environment.
- Use HTTPS in deployed environments.
- Use a real database with access controls for non-demo deployments.
- Review seeded demo data before public demos.
- Run `php artisan test` before publishing changes.

## Scope Notice

UniSOC is a demonstration SOC dashboard. It is not a hardened production incident response, SIEM, or SOAR platform without additional authentication, authorization, monitoring, deployment hardening, and operational review.
