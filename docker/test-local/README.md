# Local Zitadel SSO Harness

This directory contains a local Docker setup for testing Continuwuity with a
Zitadel identity provider.

## Local files

- `continuwuity.toml` is the live local homeserver config used by
  `docker-compose.yml`.
- `continuwuity.toml` is intentionally ignored by Git so local client IDs,
  client secrets, and other machine-specific tweaks stay out of the repository.
- `continuwuity.example.toml` is the tracked template. Copy it to
  `continuwuity.toml` when setting up the stack on a new machine.
- `shared/` is ignored by Git. Zitadel writes machine PATs there during local
  startup.

## Starting the stack

1. Copy `continuwuity.example.toml` to `continuwuity.toml`.
2. Fill in the local Zitadel OIDC app `client_id` and `client_secret`.
3. Start the harness with:

```bash
docker compose -f docker/test-local/docker-compose.yml up -d
```

The local compose file continues to mount `./continuwuity.toml`, so existing
local setups keep working without renaming files.

## Admin workflow

### Existing local Matrix users

If you want an existing Continuwuity account to land in the same Matrix account
on first SSO login, pre-populate the user-email mapping in the admin room:

```text
!admin user set-email <localpart> <email>
```

Useful companion commands:

```text
!admin user get-email <localpart>
!admin user list-emails
!admin user remove-email <localpart>
```

This mapping is the allowlist used for first-login attachment of an external
SSO identity to an existing local Matrix account.

To permit that linking path, set `trusted = true` on the identity provider in
`continuwuity.toml`. With the verified-email hardening enabled, the provider
must also assert that the email claim is verified before the mapping is used.

### New SSO users

- With `sso_allow_open_registration = true`, any authenticated Zitadel user can
  receive a new Matrix account.
- With `sso_allow_open_registration = false`, new SSO users must either:
  - have an existing admin-managed email mapping, or
  - go through the invite-token onboarding path using the `!admin token`
    commands.

### Migration notes

- Existing Matrix accounts, rooms, and history stay on Continuwuity. You are
  migrating the authentication source, not the Matrix account data.
- First SSO login to an existing Matrix account depends on the admin-managed
  email mapping above.
- After the first successful SSO login, the account is matched by the SSO
  provider identity rather than by email.
