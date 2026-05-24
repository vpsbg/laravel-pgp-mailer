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
- Optional sender signing (sign-then-encrypt) so recipients can verify the message came from you.
- A drop-in Eloquent model + migration for storing keys, with case-insensitive lookup, cache wrapping, expiry and revocation handling, and events for every key lifecycle change.
- Per-message opt-out for newsletters / receipts you intentionally want plaintext.
- Mixed audiences are handled: send one encrypted copy to the keyed recipients and an automatic plaintext copy to the rest, in a single `Mail::to(...)` call.
- A configurable missing-key policy (`passthrough` / `fail` / `drop` / `log_only`).
- A separate engine-failure policy that defaults to `drop` — engine bugs never silently leak plaintext.

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

The listener honors an `X-Pgp-Mailer-Disable: 1` header and strips it before transport. For Mailables you own, declare it the idiomatic way:

```php
use Illuminate\Mail\Mailables\Headers;

public function headers(): Headers
{
    return new Headers(text: ['X-Pgp-Mailer-Disable' => '1']);
}
```

For Mailables you don't own (third-party packages), wrap inline:

```php
use Vpsbg\PgpMailer\PgpMailer;

Mail::to($user)->send(PgpMailer::skip(new ThirdPartyNotification($data)));
```

## Signing

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

## Configuration

`config/pgp-mailer.php` documents every knob inline. The ones you'll most likely touch:

| Key | Default | What it does |
|---|---|---|
| `missing_key_policy` | `passthrough` | What to do when at least one recipient has no key on file. Options: `passthrough` / `fail` / `drop` / `log_only`. |
| `engine_failure_policy` | `drop` | What happens when encryption itself throws despite a key being present. Defaults to `drop` so engine bugs cannot silently downgrade to plaintext. |
| `signing.enabled` | `true` | Sign-then-encrypt every outgoing message with the configured sender key. |
| `gnupg_homedir` | `null` | Persistent GnuPG homedir path. When unset, an ephemeral 0700 tempdir is created per request and wiped in the destructor. |
| `model` | `PgpKey::class` | Eloquent model used by the resolver. Subclass `PgpKey` to add columns or relations, then point this at your subclass. |
| `resolver` | `EloquentKeyResolver` | The `KeyResolver` implementation. Swap to fetch keys from LDAP, WKD, an external KMS, etc. |

## Events

The package dispatches:

- `PgpKeyAdded` / `PgpKeyRotated` / `PgpKeyUidRefreshed` / `PgpKeyUidMismatch` / `PgpKeyRemoved` — key lifecycle.
- `PgpEncryptionApplied` / `PgpEncryptionFailed` — per-message outcome.

Wire these into your audit pipeline, admin notifications, or compliance log as needed.

## Testing

```bash
composer test
```

The suite covers the engine round-trip, the listener policy matrix, attachment preservation, signing, and per-message opt-out paths. The `gnupg` PECL extension must be installed.

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## License

The MIT License (MIT) — see [LICENSE.md](LICENSE.md).

> **Use at your own risk.** This package handles cryptographic material on your behalf. The MIT license disclaims all warranty: the authors and contributors are not liable for any damages, data loss, failed sends, or compliance gaps arising from its use. Audit it for your own threat model before relying on it in production.
