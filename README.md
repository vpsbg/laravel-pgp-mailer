# Laravel PGP Mailer

[![Latest Version on Packagist](https://img.shields.io/packagist/v/vpsbg/laravel-pgp-mailer.svg?style=flat-square)](https://packagist.org/packages/vpsbg/laravel-pgp-mailer)
[![GitHub Tests Action Status](https://img.shields.io/github/actions/workflow/status/vpsbg/laravel-pgp-mailer/run-tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/vpsbg/laravel-pgp-mailer/actions?query=workflow%3Arun-tests+branch%3Amain)
[![Total Downloads](https://img.shields.io/packagist/dt/vpsbg/laravel-pgp-mailer.svg?style=flat-square)](https://packagist.org/packages/vpsbg/laravel-pgp-mailer)

Transparent PGP/MIME (RFC 3156) encryption and signing for Laravel's `Mail` facade. Your users upload a public key once; every email Laravel sends them is encrypted end-to-end.

Backed by libgpgme via the [`gnupg`](https://www.php.net/manual/en/book.gnupg.php) PECL extension, so RSA, ECDSA, ECDH and Ed25519 recipient keys all work.

Here's a quick example:

```php
use Vpsbg\PgpMailer\Models\PgpKey;

PgpKey::store('alice@example.com', file_get_contents('alice.pub.asc'));

Mail::to('alice@example.com')->send(new InvoiceMail($invoice));
// → arrives as multipart/encrypted; only Alice's PGP client can read it
```

Attachments travel encrypted in the same envelope — PGP/MIME wraps the whole inner MIME blob, body + parts together.

## What you get

- Outbound mail to any address with a stored public key is automatically encrypted (RFC 3156 `multipart/encrypted`). Body and attachments alike.
- Mandatory sender signing. The package operates in one of two modes — **sign-only** or **sign+encrypt** — so authenticity always holds. Encryption requires signing; unsigned ciphertext is never produced. When signing isn't configured the listener is a no-op and mail flows untouched.
- A drop-in Eloquent model + migration for storing keys, with case-insensitive lookup, cache wrapping, expiry and revocation handling, and events for every key lifecycle change.
- Per-message opt-out for newsletters / receipts you intentionally want plaintext.
- Mixed audiences are handled: send one encrypted copy to the keyed recipients and an automatic `multipart/signed` copy to the rest, in a single `Mail::to(...)` call.
- A configurable missing-key policy (`sign_only` / `fail` / `drop`).
- A separate engine-failure policy that defaults to `drop` — engine bugs never silently downgrade to a less-secure mode.

## What it doesn't do

- **The Subject line is not encrypted.** RFC 3156 only encrypts the body; headers (Subject, From, To, Date, Message-ID, …) travel in the clear. Don't put secrets in subjects.
- **Outbound only.** This package never decrypts incoming mail.
- **Keyed by email, not by user.** One row per address — works for user emails, alternate billing/invoice addresses, shared mailboxes, role addresses. Relating keys to your own models is a one-liner; see below.
- **No in-process key generation.** A console command prints a `gpg --batch` recipe for the sender signing key; the package itself never shells out at runtime.

## Installation

The package needs the [`gnupg`](https://www.php.net/manual/en/book.gnupg.php) PECL extension (`ext-gnupg`) — installed once on the PHP host. On a Debian-based image:

```dockerfile
RUN apt-get update \
 && apt-get install -y --no-install-recommends libgpgme-dev gnupg \
 && pecl install gnupg \
 && docker-php-ext-enable gnupg
```

Then:

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

Keys are addressed by email — the host app calls the model directly. There's no trait to add to your User model.

```php
use Vpsbg\PgpMailer\Models\PgpKey;

PgpKey::store('alice@example.com', $armoredPublicKey);  // upsert + lifecycle event
PgpKey::forEmail('alice@example.com')->first();         // lookup
PgpKey::purgeEmail('alice@example.com');                // delete + PgpKeyRemoved
PgpKey::transferEmail('old@example.com', 'new@example.com');               // migrate
PgpKey::transferEmail('old@example.com', 'new@example.com', flagMismatch: true);
```

`store()` picks the right event automatically: `PgpKeyAdded` for a new row, `PgpKeyRotated` when the fingerprint changes, `PgpKeyUidRefreshed` when only the UID metadata refreshes. It validates the public key's UID against the email by default (override with `pgp-mailer.require_uid_match = false`).

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

Defaults reject malformed armor, expired keys, revoked keys, secret/private key blocks, and keys with no usable UID. Each gate has an opt-out: `->allowExpired()`, `->allowRevoked()`, `->allowSecretBlock()`. The rule performs structural validation only — `PgpKey::store()` remains the authoritative entry point for persistence and lifecycle events. Override the failure messages by publishing the translations:

```bash
php artisan vendor:publish --tag=pgp-mailer-translations
```

## Relating keys to your own models

A one-line `hasOne` on `email` covers the common case — and the same pattern handles users with separate billing/invoice addresses:

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

Opt-in. When enabled, the resolver chain will issue a single HTTP GET against a configured keyserver for any recipient whose key isn't already stored locally — synchronously, inside the `MessageSending` listener, with a short timeout. A hit is parsed via the gnupg engine, optionally persisted to `pgp_keys` (so the next send uses the local fast path), and used to encrypt the message. A miss falls back to today's `missing_key_policy`.

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

**Negative caching.** Misses (404, timeout, parse failure, UID mismatch) are cached for `negative_cache_ttl` seconds (default `3600`) under the configured `pgp-mailer.cache.store` so the same recipient is not re-fetched on every send. Set to `0` to disable.

**Concurrent first-sends.** A short-lived per-email lock coalesces concurrent fetches when many queue workers wake up to send the same newsletter. The lock uses the same cache store; in production this must be a lock-capable store (redis, memcached, database). The `pgp_keys.email` unique index is the correctness backstop if the lock store is unavailable.

Two new events fire on every fetch:

- `PgpKeyserverFetchSucceeded(string $email, Fingerprint $fingerprint, bool $persisted)`
- `PgpKeyserverFetchFailed(string $email, string $reason, ?int $httpStatus)` — `$reason` is one of `not_found`, `timeout`, `transport`, `parse_failed`, `uid_mismatch`, `expired`.

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

The resolver, scopes, and static helpers (`store`, `transferEmail`, `purgeEmail`) all flow through the configured class via late static binding.

## Opting a Mailable out

Two per-message opt-outs, both expressed as headers the listener strips before transport:

| Header | Effect | Wrapper for Mailables you don't own |
|---|---|---|
| `X-Pgp-Mailer-Disable: 1` | Skip PGP entirely — neither encrypt nor sign. | `PgpMailer::skip($mailable)` |
| `X-Pgp-Mailer-No-Encrypt: 1` | Do not encrypt, but still sign if signing is configured. Useful for signed newsletters / public announcements. | `PgpMailer::unencrypted($mailable)` |

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
| Recipient has a key, no opt-out | `multipart/encrypted` — signed-then-encrypted (signature embedded) |
| `X-Pgp-Mailer-No-Encrypt` set | `multipart/signed` — detached signature, body in the clear |
| Recipient has no key (`missing_key_policy=sign_only`) | `multipart/signed` |
| `X-Pgp-Mailer-Disable` set | Plaintext (full bypass) |
| Signing not configured globally | Plaintext (listener is a no-op) |

Configure the application's signing keypair via env:

```dotenv
PGP_MAIL_SIGN=true
PGP_MAIL_SIGNING_KEY_PATH=/path/to/signing-private.asc
PGP_MAIL_SIGNING_KEY_PASSPHRASE=
```

To generate the keypair on any host with GnuPG:

```bash
php artisan pgp-mailer:keypair --email=noreply@example.com
```

This prints a `gpg --batch` recipe you can run; the package never invokes `gpg` at runtime.

### Per-sender signing keys

When your app sends mail from more than one address — `support@app`, `billing@app`, per-tenant aliases — you can pair each From with its own signing key in `config/pgp-mailer.php`:

```php
'signing' => [
    'enabled' => env('PGP_MAIL_SIGN', true),

    // Default key — used when no per-sender entry below matches. Leave
    // these unset if every sender you actually use has its own entry.
    'key_path' => env('PGP_MAIL_SIGNING_KEY_PATH'),
    'key' => env('PGP_MAIL_SIGNING_KEY'),
    'passphrase' => env('PGP_MAIL_SIGNING_KEY_PASSPHRASE'),

    // Map: From address (case-insensitive) → signing key.
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
| `use_default` (default) | Fall back to the top-level scalar `key` / `key_path`. If that's unset too, skip signing for this message. This is the legacy single-key behavior — existing installs are unchanged. |
| `skip` | Skip signing for this sender entirely. Since encryption requires signing, the listener becomes a no-op for messages from this sender and they go out untouched. |
| `fail` | Throw `MissingSenderKeyException` and refuse to send. Use this to make every sender address explicit in config. |

**UID match is the operator's responsibility.** The package does not verify that the key you paired with `support@example.com` actually carries a UID for that address — pair them correctly when filling in `senders`.

## Configuration

`config/pgp-mailer.php` documents every knob inline. The ones you'll most likely touch:

| Key | Default | What it does |
|---|---|---|
| `missing_key_policy` | `sign_only` | What to do when at least one recipient has no key on file. Options: `sign_only` / `fail` / `drop`. |
| `engine_failure_policy` | `drop` | What happens when encryption itself throws despite a key being present. Options: `drop` / `fail`. |
| `signing.enabled` | `true` | Mandatory. When `false` (or no signing key is configured) the listener short-circuits and mail flows in plaintext. |
| `gnupg_homedir` | `null` | Persistent GnuPG homedir path. When unset, an ephemeral 0700 tempdir is created per request and wiped in the destructor. |
| `model` | `PgpKey::class` | Eloquent model used by the resolver. Subclass `PgpKey` to add columns or relations, then point this at your subclass. |
| `resolver` | `EloquentKeyResolver` | The `KeyResolver` implementation. Swap to fetch keys from LDAP, WKD, an external KMS, etc. |

## Events

The package dispatches:

- `PgpKeyAdded` / `PgpKeyRotated` / `PgpKeyUidRefreshed` / `PgpKeyUidMismatch` / `PgpKeyRemoved` — key lifecycle.
- `PgpEncryptionApplied` / `PgpEncryptionFailed` / `PgpSigningApplied` — per-message outcome. `PgpSigningApplied` fires for sign-only sends; `PgpEncryptionApplied` fires for sign+encrypt sends (its `$signed` flag is always `true` under the current model).

Wire these into your audit pipeline, admin notifications, or compliance log as needed.

## Testing

```bash
composer test
```

The suite covers the engine round-trip, the listener policy matrix, attachment preservation, signing, and per-message opt-out paths. The `gnupg` PECL extension must be installed.

## Releases

See the [GitHub Releases page](https://github.com/vpsbg/laravel-pgp-mailer/releases) for release notes per tag.

## License

The MIT License (MIT) — see [LICENSE.md](LICENSE.md).

> **Use at your own risk.** This package handles cryptographic material on your behalf. The MIT license disclaims all warranty: the authors and contributors are not liable for any damages, data loss, failed sends, or compliance gaps arising from its use. Audit it for your own threat model before relying on it in production.
