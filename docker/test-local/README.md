# Local Pocket ID SSO Harness

This directory contains a local Docker setup for testing Continuwuity with a
Pocket ID identity provider.

## Local files

- `continuwuity.toml` is the live local homeserver config used by
  `docker-compose.yml`.
- `continuwuity.toml` is intentionally ignored by Git so local client IDs,
  client secrets, and other machine-specific tweaks stay out of the repository.
- `continuwuity.example.toml` is the tracked template. Copy it to
  `continuwuity.toml` when setting up the stack on a new machine.
- `shared/` is ignored by Git. This harness keeps the Pocket ID encryption key,
  static API key, and generated Continuwuity OIDC client secret there.

## Starting the stack

1. Start Pocket ID first:

```bash
cd docker/test-local
docker compose up -d pocket-id
```

2. Bootstrap or rotate the fixed local OIDC client that Continuwuity expects:

```bash
node ./pocket-id-admin.mjs bootstrap-client
```

3. Start the rest of the harness:

```bash
docker compose up -d
```

The local compose file continues to mount `./continuwuity.toml`, so existing
local setups keep working without renaming files.

## Invite flow

- Continuwuity native registration stays disabled with `allow_registration = false`.
- SSO auto-provisioning stays enabled with `sso_allow_open_registration = true`.
- Pocket ID is the actual invite gate. Users must receive a Pocket ID signup
  token first, then their first successful SSO login creates the Matrix account.
- Because Pocket ID signup is token-based, the Matrix "Register" button does
  not map to a public Pocket ID registration page in this harness.

Create a Pocket ID signup-token invite link with:

```bash
node ./pocket-id-admin.mjs create-signup-token --ttl 24h --usage-limit 1
```

That prints a `https://localhost:8443/signup?token=...` link you can hand to
the invited user.

Once Continuwuity is rebuilt with the in-tree Pocket ID invite integration,
admins can mint the same kind of signup link from the admin room with:

```text
!admin sso-invite issue --ttl 24h --usage-limit 1
```

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

- With `sso_allow_open_registration = true`, any authenticated Pocket ID user
  can receive a new Matrix account.
- With `sso_allow_open_registration = false`, new SSO users must either:
  - have an existing admin-managed email mapping, or
  - go through the invite-token onboarding path using the `!admin token`
    commands.

Pocket ID invite tokens and Continuwuity `!admin token` invites are separate
gates. The intended local flow here is:

- Pocket ID signup token controls who can create an identity.
- Continuwuity SSO auto-provisioning creates the Matrix account on first login.

### Migration notes

- Existing Matrix accounts, rooms, and history stay on Continuwuity. You are
  migrating the authentication source, not the Matrix account data.
- First SSO login to an existing Matrix account depends on the admin-managed
  email mapping above.
- After the first successful SSO login, the account is matched by the SSO
  provider identity rather than by email.
