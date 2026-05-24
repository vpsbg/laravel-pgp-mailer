<?php

declare(strict_types=1);

use Vpsbg\PgpMailer\Models\PgpKey;
use Vpsbg\PgpMailer\Resolvers\EloquentKeyResolver;

return [

    // Master switch. When false, the listener short-circuits and mail flows
    // in plaintext. For routine "this recipient has no key" handling, use
    // missing_key_policy below instead.
    'enabled' => env('PGP_MAIL_ENABLED', true),

    // Optional path to a persistent GnuPG homedir. When null (default), the
    // engine creates an ephemeral 0700 tempdir per request and wipes it in
    // its destructor. Set this only if you want a long-lived keyring managed
    // by an operator (must be chmod 0700 and owned by the PHP-FPM user).
    'gnupg_homedir' => env('PGP_MAIL_GNUPG_HOMEDIR'),

    // Resolves recipient email → ArmoredKey. Swap to read from LDAP, WKD,
    // an external KMS, etc. without touching the listener.
    'resolver' => EloquentKeyResolver::class,

    'table' => 'pgp_keys',

    // Eloquent model class. Subclass PgpKey if you want extra columns,
    // additional relationships, or to override scopes/casts, then point this
    // at your subclass.
    'model' => PgpKey::class,

    'cache' => [
        'enabled' => true,
        'store' => null,
        'ttl' => 60 * 60,
        'prefix' => 'pgp-mailer:key:',
    ],

    /*
    | What to do when at least one recipient has no usable key:
    |   passthrough — encrypt for those who have keys, plaintext to the rest
    |                 (or fully plaintext if nobody has a key)
    |   fail        — throw MissingRecipientKeyException; nothing is sent
    |   drop        — silently drop the message; transport is never invoked
    |   log_only    — log a warning, then send plaintext
    */
    'missing_key_policy' => env('PGP_MAIL_MISSING_KEY_POLICY', 'passthrough'),

    /*
    | Distinct from missing_key_policy: applies when the recipient HAS a key
    | but encryption itself throws (malformed stored key, transient libgpgme
    | error, etc.). Defaults to `drop` so a misbehaving engine never silently
    | downgrades to plaintext.
    |   drop     — short-circuit; don't send anything (safest)
    |   fail     — re-throw the engine exception
    |   log_only — log a warning and send plaintext (DANGEROUS; explicit opt-in)
    */
    'engine_failure_policy' => env('PGP_MAIL_ENGINE_FAILURE_POLICY', 'drop'),

    'passthrough' => [
        // When true and recipients are mixed, send two messages: one encrypted
        // bundle to keyed recipients, one plaintext to the rest. When false,
        // a single mixed audience falls back to one plaintext send.
        'split_recipients' => true,
    ],

    /*
    | Sender signing key. Provide either the armored private key inline
    | (PGP_MAIL_SIGNING_KEY) or a filesystem path (PGP_MAIL_SIGNING_KEY_PATH).
    | Path wins if both are set. The passphrase is held in config like any
    | other secret — it is NOT zeroed from PHP memory after use.
    */
    'signing' => [
        'enabled' => env('PGP_MAIL_SIGN', true),
        'key_path' => env('PGP_MAIL_SIGNING_KEY_PATH'),
        'key' => env('PGP_MAIL_SIGNING_KEY'),
        'passphrase' => env('PGP_MAIL_SIGNING_KEY_PASSPHRASE'),
    ],

    'require_uid_match' => true,

    'expiry' => [
        'reject_expired' => true,
        'reject_revoked' => true,
    ],

    /*
    | Per-message opt-out. Any outgoing email carrying the header
    | `X-Pgp-Mailer-Disable: 1` bypasses encryption. The header is stripped
    | before transport so it never reaches the recipient.
    |
    | Set it the idiomatic way on a Mailable you own:
    |
    |   public function headers(): \Illuminate\Mail\Mailables\Headers
    |   {
    |       return new \Illuminate\Mail\Mailables\Headers(text: [
    |           'X-Pgp-Mailer-Disable' => '1',
    |       ]);
    |   }
    |
    | For Mailables you don't own, wrap inline:
    |
    |   Mail::to($u)->send(\Vpsbg\PgpMailer\PgpMailer::skip(new ThirdPartyMail(...)));
    */

    'log_channel' => env('PGP_MAIL_LOG_CHANNEL'),

];
