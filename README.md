<div align="center">

# Laravel PGP Mailer

**PGP/MIME encryption and signing for Laravel's `Mail` facade.**

[![Latest Version on Packagist](https://img.shields.io/packagist/v/vpsbg/laravel-pgp-mailer.svg?style=flat-square)](https://packagist.org/packages/vpsbg/laravel-pgp-mailer)
[![GitHub Tests Action Status](https://img.shields.io/github/actions/workflow/status/vpsbg/laravel-pgp-mailer/run-tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/vpsbg/laravel-pgp-mailer/actions?query=workflow%3Arun-tests+branch%3Amain)
[![Total Downloads](https://img.shields.io/packagist/dt/vpsbg/laravel-pgp-mailer.svg?style=flat-square)](https://packagist.org/packages/vpsbg/laravel-pgp-mailer)

</div>

---

Send PGP-encrypted email from Laravel without touching your Mailables. Store a recipient's public key once and every `Mail::to(...)` after that goes out as a signed RFC 3156 `multipart/encrypted` message - body and attachments included.

Works with RSA, ECDSA, ECDH and Ed25519 keys via the [`gnupg`](https://www.php.net/manual/en/book.gnupg.php) PECL extension. Outbound only - the package never decrypts incoming mail.

```php
use Vpsbg\PgpMailer\Models\PgpKey;

PgpKey::store('alice@example.com', file_get_contents('alice.pub.asc'));

Mail::to('alice@example.com')->send(new InvoiceMail($invoice));
// arrives as multipart/encrypted; only Alice's PGP client can read it
```

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Storing keys](#storing-keys)
- [Relating keys to your own models](#relating-keys-to-your-own-models)
- [Keyserver auto-fetch](#keyserver-auto-fetch)
- [Extending the model](#extending-the-model)
- [Opting a Mailable out](#opting-a-mailable-out)
- [Signing](#signing)
- [Encrypted Subjects](#encrypted-subjects)
- [Configuration](#configuration)
- [Events](#events)
- [Testing](#testing)
- [Changelog](#changelog)
- [Contributing](#contributing)
- [Security Vulnerabilities](#security-vulnerabilities)
- [License](#license)

## Features

- Outbound mail to any address with a stored public key is automatically encrypted (RFC 3156 `multipart/encrypted`). Body and attachments alike.
- Mandatory sender signing. The package operates in one of two modes - **sign-only** or **sign+encrypt** - so authenticity always holds. Encryption requires signing; unsigned ciphertext is never produced. When signing isn't configured the listener is a no-op and mail flows untouched.
- A drop-in Eloquent model + migration for storing keys, with case-insensitive lookup, cache wrapping, expiry and revocation handling, and events for every key lifecycle change.
- Per-message opt-out for newsletters, receipts, and announcements: bypass PGP entirely (plaintext) or keep the signature but drop encryption (signed `multipart/signed`).
- Mixed audiences are handled: send one encrypted copy to the keyed recipients and an automatic `multipart/signed` copy to the rest, in a single `Mail::to(...)` call.
- A configurable missing-key policy (`sign_only` / `fail` / `drop`).
- A separate engine-failure policy that defaults to `drop` - engine bugs never silently downgrade to a less-secure mode.

## Installation

The package needs the [`gnupg`](https://www.php.net/manual/en/book.gnupg.php) PECL extension (`ext-gnupg`), installed once on the PHP host. On a Debian-based image:

```dockerfile
RUN apt-get update \
 && apt-get install -y --no-install-recommends libgpgme-dev gnupg \
 && pecl install gnupg \
 && docker-php-ext-enable gnupg
```

Install the package:

```bash
composer require vpsbg/laravel-pgp-mailer
```

Publish the config file:

```bash
php artisan vendor:publish --provider="Vpsbg\PgpMailer\PgpMailerServiceProvider" --tag="config"
```

Publish and run the migration:

```bash
php artisan vendor:publish --provider="Vpsbg\PgpMailer\PgpMailerServiceProvider" --tag="migrations"
php artisan migrate
```

## Storing keys

Keys are addressed by email - the host app calls the model directly. There's no trait to add to your User model.

```php
use Vpsbg\PgpMailer\Models\PgpKey;

PgpKey::store('alice@example.com', $armoredPublicKey);  // upsert + lifecycle event
PgpKey::forEmail('alice@example.com')->first();         // lookup
PgpKey::purgeEmail('alice@example.com');                // delete + PgpKeyRemoved
PgpKey::transferEmail('old@example.com', 'new@example.com');               // migrate
PgpKey::transferEmail('old@example.com', 'new@example.com', flagMismatch: true);
```

`store()` picks the right event automatically: `PgpKeyAdded` for a new row, `PgpKeyRotated` when the fingerprint changes, `PgpKeyUidRefreshed` when only the UID metadata refreshes. It validates the public key's UID against the email by default (override with `pgp-mailer.require_uid_match = false`).

`transferEmail()` moves a stored key from one address to another. Pass `flagMismatch: true` when the new address is not guaranteed to appear in the key's UID - typical for "user changed their account email" - and the row is marked suspect:

- `uid_mismatch_at` is stamped on the row so the discrepancy is visible to admin tooling.
- `PgpKeyUidMismatch` fires so the host can prompt the user to upload a re-signed key with the new address.
- When the user later re-uploads the key via `PgpKey::store($newEmail, $armored)`, the store path sees the same fingerprint and a non-null `uid_mismatch_at`, clears the flag, and dispatches `PgpKeyUidRefreshed` instead of treating the upload as a rotation.

Pass `flagMismatch: false` (the default) only when the underlying key already carries the new address in its UID - for example, correcting a typo in how the email was originally stored.

### Validating uploads

When you accept an armored public key from a user (profile form, admin upload, API endpoint), use `ValidPgpKey` alongside Laravel's built-in rules so failures surface as ordinary field errors instead of exceptions:

```php
use Vpsbg\PgpMailer\Rules\ValidPgpKey;

$request->validate([
    'pgp_key' => ['required', 'string', 'max:65535', new ValidPgpKey],
]);
```

When `pgp-mailer.require_uid_match` is enabled (the default), pass the expected address via `->forEmail()` so the rule rejects keys whose UIDs point elsewhere:

```php
$request->validate([
    'email'   => ['required', 'email'],
    'pgp_key' => ['required', 'string', (new ValidPgpKey)->forEmail($request->input('email'))],
]);
```

Defaults reject malformed armor, expired keys, revoked keys, secret/private key blocks, and keys with no usable UID. Each gate has an opt-out: `->allowExpired()`, `->allowRevoked()`, `->allowSecretBlock()`. The rule performs structural validation only - `PgpKey::store()` remains the authoritative entry point for persistence and lifecycle events. Override the failure messages by publishing the translations:

```bash
php artisan vendor:publish --provider="Vpsbg\PgpMailer\PgpMailerServiceProvider" --tag="translations"
```

## Relating keys to your own models

A one-line `hasOne` on `email` covers the common case, and the same pattern handles users with separate billing/invoice addresses:

```php
use Vpsbg\PgpMailer\Models\PgpKey;

class User extends Authenticatable
{
    public function pgpKey()        { return $this->hasOne(PgpKey::class, 'email', 'email'); }
    public function invoicePgpKey() { return $this->hasOne(PgpKey::class, 'email', 'invoice_email'); }
}
```

If you want a stored key to follow (or be cleaned up after) your model, wire your own observer:

```php
User::updating(function (User $u) {
    if ($u->isDirty('email')) {
        PgpKey::transferEmail($u->getOriginal('email'), $u->email, flagMismatch: true);
    }
});

User::deleting(fn (User $u) => PgpKey::purgeEmail($u->email));
```

## Keyserver auto-fetch

Opt-in. When enabled, the resolver chain will issue a single HTTP GET against a configured keyserver for any recipient whose key isn't already stored locally - synchronously, inside the `MessageSending` listener, with a short timeout. A hit is parsed via the gnupg engine, optionally persisted to `pgp_keys` (so the next send uses the local fast path), and used to encrypt the message. A miss falls back to today's `missing_key_policy`.

The default URL targets [keys.openpgp.org](https://keys.openpgp.org)'s VKS API; an HKP URL works equally well.

```dotenv
PGP_MAIL_KEYSERVER_ENABLED=true
PGP_MAIL_KEYSERVER_URL=https://keys.openpgp.org/vks/v1/by-email/{email}
# Or HKP:
# PGP_MAIL_KEYSERVER_URL=https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search={email}
PGP_MAIL_KEYSERVER_TIMEOUT=3
PGP_MAIL_KEYSERVER_PERSIST=true
```

`{email}` is URL-encoded before substitution.

**Trust model.** The package cannot verify what kind of policy a keyserver enforces before publishing keys. VKS-style servers like keys.openpgp.org confirm email ownership; SKS-style HKP servers do not. The operator picks the server URL and accepts that trade-off. Default `verify_tls` is `true` and there is no quiet self-signed acceptance.

**`require_uid_match` still applies.** If the fetched key's UID does not contain the recipient address, the resolver discards it, emits `PgpKeyserverFetchFailed(reason="uid_mismatch")`, negative-caches the miss, and lets `missing_key_policy` take over. Set `pgp-mailer.require_uid_match` to `false` only if you trust the upstream's identity binding.

**Negative caching.** Every miss (404, timeout, transport error, parse failure, UID mismatch, expired key, revoked key) is cached for `negative_cache_ttl` seconds (default `3600`) under the configured `pgp-mailer.cache.store` so the same recipient is not re-fetched on every send. Set to `0` to disable.

**Concurrent first-sends.** A short-lived per-email lock coalesces concurrent fetches when many queue workers wake up to send the same newsletter. The lock uses the same cache store; in production this must be a lock-capable store (redis, memcached, database). The `pgp_keys.email` unique index is the correctness backstop if the lock store is unavailable.

Two new events fire on every fetch:

- `PgpKeyserverFetchSucceeded(string $email, Fingerprint $fingerprint, bool $persisted)`
- `PgpKeyserverFetchFailed(string $email, string $reason, ?int $httpStatus)` - `$reason` is one of `not_found`, `timeout`, `transport`, `parse_failed`, `uid_mismatch`, `expired`, `revoked`.

The resolver never throws to the listener; every failure mode resolves to null + an event.

## Extending the model

Need extra columns or relations on the key row? Subclass `PgpKey`, then point `pgp-mailer.model` at your subclass:

```php
namespace App\Models;

class TenantPgpKey extends \Vpsbg\PgpMailer\Models\PgpKey
{
    public function tenant() { return $this->belongsTo(Tenant::class); }
}
```

```php
// config/pgp-mailer.php
'model' => App\Models\TenantPgpKey::class,
```

The resolver reads `pgp-mailer.model` to pick the class it loads rows as. The static helpers (`store`, `transferEmail`, `purgeEmail`) use plain late static binding: call them on the subclass (`TenantPgpKey::store(...)`) and you get subclass instances; call them on the base `PgpKey` and you get base-class rows regardless of the config.

## Opting a Mailable out

Two per-message opt-outs, both expressed as headers the listener strips before transport:

| Header | Effect | Wrapper for Mailables you don't own |
|---|---|---|
| `X-Pgp-Mailer-Disable: 1` | Skip PGP entirely - neither encrypt nor sign. | `PgpMailer::skip($mailable)` |
| `X-Pgp-Mailer-No-Encrypt: 1` | Do not encrypt, but still sign if signing is configured. Useful for signed newsletters and public announcements. | `PgpMailer::unencrypted($mailable)` |

For Mailables you own, declare the header the idiomatic way:

```php
use Illuminate\Mail\Mailables\Headers;

public function headers(): Headers
{
    return new Headers(text: ['X-Pgp-Mailer-Disable' => '1']);
    // or: ['X-Pgp-Mailer-No-Encrypt' => '1']
}
```

For Mailables you don't own (third-party packages), wrap inline:

```php
use Vpsbg\PgpMailer\PgpMailer;

Mail::to($user)->send(PgpMailer::skip(new ThirdPartyNotification($data)));
Mail::to($user)->send(PgpMailer::unencrypted(new MonthlyDigestMail($data)));
```

## Signing

Signing is mandatory: the package only produces `multipart/encrypted` (sign+encrypt) or `multipart/signed` output. When signing isn't configured globally, the listener is a no-op and mail flows untouched.

| Situation | Wire format |
|---|---|
| Recipient has a key, no opt-out | `multipart/encrypted` - signed-then-encrypted (signature embedded) |
| `X-Pgp-Mailer-No-Encrypt` set | `multipart/signed` - detached signature, body in the clear |
| Recipient has no key (`missing_key_policy=sign_only`) | `multipart/signed` |
| `X-Pgp-Mailer-Disable` set | Plaintext (full bypass) |
| Signing not configured globally | Plaintext (listener is a no-op) |

Configure the application's signing keypair via env:

```dotenv
PGP_MAIL_SIGN=true
PGP_MAIL_SIGNING_KEY_PATH=/path/to/signing-private.asc
PGP_MAIL_SIGNING_KEY_PASSPHRASE=
```

### Generating the signing keypair

Generate the keypair once on any host that has GnuPG installed, copy the exported `.asc` files into your deployment, and point `PGP_MAIL_SIGNING_KEY_PATH` at the private key. The recipe below produces an Ed25519 primary (`sign,cert`) plus a Curve25519 encryption subkey (`encr`) with no passphrase that never expires - the conventional PGP key shape, small and fast, with file-mode `0600` as the access control.

```bash
mkdir -p storage/pgp
EMAIL="noreply@example.com"

# 1. Primary key: Ed25519, sign + certify, no expiry, no passphrase.
gpg --batch --pinentry-mode loopback --passphrase "" \
    --quick-generate-key "Your App <$EMAIL>" ed25519 sign,cert 0

# 2. Grab the fingerprint of the key we just generated.
FPR=$(gpg --with-colons --list-keys "$EMAIL" | awk -F: '/^fpr:/ {print $10; exit}')

# 3. Add a Curve25519 encryption subkey (so the key can also be encrypted to).
gpg --batch --pinentry-mode loopback --passphrase "" \
    --quick-add-key "$FPR" cv25519 encr 0

# 4. Export private and public halves.
gpg --armor --export-secret-keys "$FPR" > storage/pgp/signing-private.asc
gpg --armor --export             "$FPR" > storage/pgp/signing-public.asc
chmod 600 storage/pgp/signing-private.asc
```

The `--passphrase ""` + `--pinentry-mode loopback` pair creates the key with no passphrase, which is appropriate for a service signing key whose file permissions are the access control. To passphrase-protect the key instead, drop both flags from every `gpg` call above, let gpg prompt you interactively, and set `PGP_MAIL_SIGNING_KEY_PASSPHRASE` in your `.env`. The trailing `0` in each call is the expiry (`0` = never; `2y`, `1y`, `30d` also accepted).

> Strictly speaking the package only needs the signing capability - if you don't plan to publish this key for inbound encryption, you can skip step 3. Prefer RSA? Swap `ed25519 sign,cert 0` for `rsa4096 sign 0` and `cv25519 encr 0` for `rsa4096 encr 0`. The package handles both - Ed25519 is just the modern default.

### Pasting the key inline (env / secrets managers)

If you'd rather not ship the `.asc` file alongside your deployment - typical on Fly.io, Heroku, ECS, GitHub Actions, Vault, AWS/GCP Secrets Manager, etc. - use `PGP_MAIL_SIGNING_KEY` instead of `PGP_MAIL_SIGNING_KEY_PATH` and paste the private key directly. ASCII armor is multi-line, which most env loaders and secret stores reject or mangle, so **base64-encode the armor** first:

```bash
base64 -w0 storage/pgp/signing-private.asc      # GNU coreutils (Linux)
base64    < storage/pgp/signing-private.asc | tr -d '\n'   # macOS / BSD
```

Paste the resulting single line into your secret store as `PGP_MAIL_SIGNING_KEY_B64`, then decode it where the config reads it:

```php
// config/pgp-mailer.php
'signing' => [
    'enabled' => env('PGP_MAIL_SIGN', true),
    'key' => ($b64 = env('PGP_MAIL_SIGNING_KEY_B64'))
        ? base64_decode($b64, true)
        : env('PGP_MAIL_SIGNING_KEY'),
    'passphrase' => env('PGP_MAIL_SIGNING_KEY_PASSPHRASE'),
    // ...
],
```

`signing.key_path` still wins if both are set, so unset it (or omit `PGP_MAIL_SIGNING_KEY_PATH`) when going env-only.

### Per-sender signing keys

When your app sends mail from more than one address - `support@app`, `billing@app`, per-tenant aliases - you can pair each From with its own signing key in `config/pgp-mailer.php`:

```php
'signing' => [
    'enabled' => env('PGP_MAIL_SIGN', true),

    // Default key. Used when no per-sender entry below matches. Leave
    // these unset if every sender you actually use has its own entry.
    'key_path' => env('PGP_MAIL_SIGNING_KEY_PATH'),
    'key' => env('PGP_MAIL_SIGNING_KEY'),
    'passphrase' => env('PGP_MAIL_SIGNING_KEY_PASSPHRASE'),

    // Map: From address (case-insensitive) to signing key.
    'senders' => [
        'support@example.com' => [
            'key_path' => env('PGP_MAIL_SIGNING_KEY_SUPPORT_PATH'),
            'passphrase' => env('PGP_MAIL_SIGNING_KEY_SUPPORT_PASSPHRASE'),
        ],
        'billing@example.com' => [
            'key_path' => env('PGP_MAIL_SIGNING_KEY_BILLING_PATH'),
            'passphrase' => env('PGP_MAIL_SIGNING_KEY_BILLING_PASSPHRASE'),
        ],
    ],

    'unmatched_sender_policy' => env('PGP_MAIL_UNMATCHED_SENDER_POLICY', 'use_default'),
],
```

Each entry uses the same `key` / `key_path` / `passphrase` shape as the top-level scalar block. Lookups happen on the message's first `From` address; wildcards and domain-level matches are intentionally not supported, so the pairing in your config stays self-documenting.

When the message's From has no entry in `senders`, the resolver applies `unmatched_sender_policy`:

| Policy | What it does |
|---|---|
| `use_default` (default) | Fall back to the top-level scalar `key` / `key_path`. If that's unset too, skip signing for this message. This is the legacy single-key behavior - existing installs are unchanged. |
| `skip` | Skip signing for this sender entirely. Since encryption requires signing, the listener becomes a no-op for messages from this sender and they go out untouched. |
| `fail` | Throw `MissingSenderKeyException` and refuse to send. Use this to make every sender address explicit in config. |

**UID match is the operator's responsibility.** The package does not verify that the key you paired with `support@example.com` actually carries a UID for that address - pair them correctly when filling in `senders`.

## Encrypted Subjects

By default, RFC 3156 leaves the `Subject` (and every other outer header) readable on the wire. The package can additionally encrypt the Subject via **Protected Headers** ([draft-ietf-lamps-header-protection](https://datatracker.ietf.org/doc/draft-ietf-lamps-header-protection/)), an IETF draft that is not yet finalized. MUA support is uneven, so the feature is opt-in.

When enabled, the listener copies the outer Subject into the encrypted-or-signed inner MIME part and rewrites the outer Subject to a configurable placeholder. The inner part is marked both with `Content-Type: ...; protected-headers="v1"` (per the draft) and with the legacy "memory-hole" `Subject:` header, so clients implementing either convention can display the real Subject after decryption. **Tested MUA: Thunderbird.** Other clients may or may not honor the inner Subject - if they don't, the body still decrypts normally and the placeholder shows in the inbox list.

Enable globally via env:

```dotenv
PGP_MAIL_PROTECTED_HEADERS=true
PGP_MAIL_PROTECTED_HEADERS_PLACEHOLDER="Encrypted Subject"
```

For specific messages where the Subject must stay visible (transactional receipts, password resets, anything readers scan in their inbox without opening), opt out per-send:

| Header | Wrapper | Effect |
|---|---|---|
| `X-Pgp-Mailer-Visible-Subject: 1` | `PgpMailer::withVisibleSubject($mailable)` | Keep the outer Subject visible for this message even when Protected Headers are enabled globally. No-op when the feature is off. |

```php
use Vpsbg\PgpMailer\PgpMailer;

Mail::to($user)->send(PgpMailer::withVisibleSubject(new PasswordResetMail($token)));
```

## Configuration

`config/pgp-mailer.php` documents every knob inline. The ones you'll most likely touch:

| Key | Default | What it does |
|---|---|---|
| `enabled` | `true` | Top-level kill switch. When `false`, the `MessageSending` listener is not registered at all and mail flows untouched. Distinct from `signing.enabled` below, which short-circuits the listener once registered. |
| `missing_key_policy` | `sign_only` | What to do when at least one recipient has no key on file. Options: `sign_only` / `fail` / `drop`. |
| `engine_failure_policy` | `drop` | What happens when encryption itself throws despite a key being present. Options: `drop` / `fail`. |
| `signing.enabled` | `true` | Mandatory. When `false` (or no signing key is configured) the listener short-circuits and mail flows in plaintext. |
| `gnupg_homedir` | `null` | Persistent GnuPG homedir path. When unset, an ephemeral 0700 tempdir is created per request and wiped in the destructor. |
| `model` | `PgpKey::class` | Eloquent model used by the resolver. Subclass `PgpKey` to add columns or relations, then point this at your subclass. |
| `resolver` | `EloquentKeyResolver` | The `KeyResolver` implementation. Swap to fetch keys from LDAP, WKD, an external KMS, etc. |

## Events

The package dispatches:

- `PgpKeyAdded` / `PgpKeyRotated` / `PgpKeyUidRefreshed` / `PgpKeyUidMismatch` / `PgpKeyRemoved` - key lifecycle.
- `PgpEncryptionApplied` / `PgpEncryptionFailed` / `PgpSigningApplied` - per-message outcome. `PgpSigningApplied` fires for sign-only sends; `PgpEncryptionApplied` fires for sign+encrypt sends (its `$signed` flag is always `true` under the current model).
- `PgpKeyserverFetchSucceeded` / `PgpKeyserverFetchFailed` - per-fetch outcome from the optional keyserver resolver. See [Keyserver auto-fetch](#keyserver-auto-fetch) for the payload shapes and the full `$reason` enumeration.

Wire these into your audit pipeline, admin notifications, or compliance log as needed.

## Testing

```bash
composer test
```

The suite covers the engine round-trip, the listener policy matrix, attachment preservation, signing, and per-message opt-out paths. The `gnupg` PECL extension must be installed.

## Changelog

Release notes for every tagged version live on the [GitHub Releases page](https://github.com/vpsbg/laravel-pgp-mailer/releases).

## Contributing

Bug reports, feature requests and pull requests are welcome. Please open an issue first to discuss anything non-trivial, then run `composer test` locally before submitting a PR. Conventional Commit-style subjects are preferred (`feat(engine): ...`, `fix(listener): ...`, `docs: ...`).

## Security Vulnerabilities

If you discover a security vulnerability, please **do not** open a public issue. Use GitHub's [private vulnerability reporting](https://github.com/vpsbg/laravel-pgp-mailer/security/advisories/new) on this repository instead.

## License

The MIT License (MIT). See [LICENSE.md](LICENSE.md) for the full text.

> **Use at your own risk.** This package handles cryptographic material on your behalf. The MIT license disclaims all warranty: the authors and contributors are not liable for any damages, data loss, failed sends, or compliance gaps arising from its use. Audit it for your own threat model before relying on it in production.
