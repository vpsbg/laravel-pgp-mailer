<?php

declare(strict_types=1);

use Vpsbg\PgpMailer\Models\PgpKey;
use Vpsbg\PgpMailer\Resolvers\EloquentKeyResolver;

return [

    // Master switch. When false (or when signing is not configured below),
    // the listener short-circuits and mail flows in plaintext. The package
    // only operates in sign-only or sign+encrypt modes — encryption requires
    // signing, and unsigned ciphertext is never produced. For routine
    // "this recipient has no key" handling, use missing_key_policy below.
    'enabled' => env('PGP_MAIL_ENABLED', true),

    // Optional path to a persistent GnuPG homedir. When null (default), the
    // engine creates an ephemeral 0700 tempdir per request and wipes it in
    // its destructor. Set this only if you want a long-lived keyring managed
    // by an operator (must be chmod 0700 and owned by the PHP-FPM user).
    'gnupg_homedir' => env('PGP_MAIL_GNUPG_HOMEDIR'),

    // Resolves recipient email → ArmoredKey. Swap to read from LDAP, WKD,
    // an external KMS, etc. without touching the listener.
    'resolver' => EloquentKeyResolver::class,

    // Database table that backs the default EloquentKeyResolver. Rename
    // if your migrations published it under a different name.
    'table' => 'pgp_keys',

    // Eloquent model class. Subclass PgpKey if you want extra columns,
    // additional relationships, or to override scopes/casts, then point this
    // at your subclass.
    'model' => PgpKey::class,

    // Resolver-level cache of email → ArmoredKey lookups. Disable for
    // tests, or point at a dedicated store to keep PGP keys out of the
    // shared application cache.
    'cache' => [
        // Master switch for the resolver cache.
        'enabled' => true,
        // Cache store name (from config/cache.php). Null uses the
        // application's default store.
        'store' => null,
        // TTL in seconds. Lookups are invalidated explicitly on
        // PgpKey::store / ::transferEmail / ::purgeEmail, so a long TTL is
        // safe.
        'ttl' => 60 * 60,
        // Key prefix; appended with the lowercased email.
        'prefix' => 'pgp-mailer:key:',
    ],

    /*
    | What to do when at least one recipient has no usable key:
    |   sign_only — encrypt for those who have keys, multipart/signed to the
    |               rest (or fully sign-only if nobody has a key)
    |   fail      — throw MissingRecipientKeyException; nothing is sent
    |   drop      — silently drop the message; transport is never invoked
    */
    'missing_key_policy' => env('PGP_MAIL_MISSING_KEY_POLICY', 'sign_only'),

    /*
    | Distinct from missing_key_policy: applies when the recipient HAS a key
    | but encryption itself throws (malformed stored key, transient libgpgme
    | error, etc.). Defaults to `drop` so a misbehaving engine never falls
    | back to a less-secure mode.
    |   drop — short-circuit; don't send anything (safest)
    |   fail — re-throw the engine exception
    */
    'engine_failure_policy' => env('PGP_MAIL_ENGINE_FAILURE_POLICY', 'drop'),

    'sign_only' => [
        // When true and recipients are mixed, send two messages: one
        // encrypted bundle to keyed recipients, one multipart/signed copy
        // to the rest. When false, a single mixed audience falls back to
        // one multipart/signed send to everyone.
        'split_recipients' => true,
    ],

    /*
    | Sender signing keys.
    |
    | The top-level `key` / `key_path` / `passphrase` describe the default
    | signing key used when no per-sender entry below matches the message's
    | From address. Provide the private key inline (PGP_MAIL_SIGNING_KEY) or
    | as a filesystem path (PGP_MAIL_SIGNING_KEY_PATH); path wins if both
    | are set. Passphrases are held in config like any other secret — they
    | are NOT zeroed from PHP memory after use.
    |
    | To sign messages from multiple From addresses with the matching key
    | per sender, fill in `senders`. The lookup is case-insensitive on the
    | full email address; wildcards / domain matches are intentionally not
    | supported so the pairing stays self-documenting. Each entry uses the
    | same `key` / `key_path` / `passphrase` shape as the default block.
    |
    |   'senders' => [
    |       'support@example.com' => [
    |           'key_path' => env('PGP_MAIL_SIGNING_KEY_SUPPORT_PATH'),
    |           'passphrase' => env('PGP_MAIL_SIGNING_KEY_SUPPORT_PASSPHRASE'),
    |       ],
    |       'billing@example.com' => [
    |           'key_path' => env('PGP_MAIL_SIGNING_KEY_BILLING_PATH'),
    |           'passphrase' => env('PGP_MAIL_SIGNING_KEY_BILLING_PASSPHRASE'),
    |       ],
    |   ],
    |
    | When the message's From has no entry in `senders`, the resolver applies
    | `unmatched_sender_policy`:
    |   use_default — fall back to the default key above (current behavior;
    |                 if no default is configured, signing is skipped for
    |                 this message)
    |   skip        — silently skip signing this message (still encrypt
    |                 when recipient keys exist)
    |   fail        — throw MissingSenderKeyException; refuse to send
    */
    'signing' => [
        // Master switch. Must be true AND a key source must be configured
        // for the listener to do anything — otherwise it is a no-op.
        'enabled' => env('PGP_MAIL_SIGN', true),
        // Filesystem path to the default signing private key (ASCII-armored).
        // Wins over `key` when both are set.
        'key_path' => env('PGP_MAIL_SIGNING_KEY_PATH'),
        // Inline ASCII-armored default signing private key. Use when a
        // filesystem path isn't practical (e.g. secrets injected via env).
        'key' => env('PGP_MAIL_SIGNING_KEY'),
        // Passphrase for the default signing key. Null for unprotected keys.
        'passphrase' => env('PGP_MAIL_SIGNING_KEY_PASSPHRASE'),
        // Optional per-sender map: From address → signing-key config block
        // (same `key` / `key_path` / `passphrase` shape as above). See the
        // long comment above for layout.
        'senders' => [],
        // What the resolver does when the message's From has no entry in
        // `senders`: use_default | skip | fail. See comment block above.
        'unmatched_sender_policy' => env('PGP_MAIL_UNMATCHED_SENDER_POLICY', 'use_default'),
    ],

    /*
    | Synchronous public-key auto-fetch from a remote keyserver. Opt-in; off by
    | default. When enabled and an outgoing recipient has no row in pgp_keys,
    | the resolver chain falls through to a single HTTP GET against
    | `url_template` (with `{email}` URL-encoded and substituted). A 200 +
    | ASCII-armored body is parsed via the gnupg engine; if `persist` is true
    | (default), it is stored via PgpKey::store() so subsequent sends use the
    | local fast path. Any failure (404, timeout, parse error, UID mismatch)
    | falls back to today's missing_key_policy — the resolver never throws.
    |
    | Trust caveat: the package cannot verify a server's verification policy.
    | VKS servers like keys.openpgp.org confirm email ownership before
    | publishing keys; SKS-style HKP servers do not. The operator picks the
    | URL and accepts that trade-off.
    */
    'keyserver' => [
        // Master switch. When false, the resolver chain reduces to the
        // configured `resolver` above and no HTTP calls happen.
        'enabled' => env('PGP_MAIL_KEYSERVER_ENABLED', false),
        // GET URL template. `{email}` is replaced with the URL-encoded
        // recipient address. Examples:
        //   VKS (keys.openpgp.org): https://keys.openpgp.org/vks/v1/by-email/{email}
        //   HKP:                    https://keyserver.ubuntu.com/pks/lookup?op=get&options=mr&search={email}
        'url_template' => env(
            'PGP_MAIL_KEYSERVER_URL',
            'https://keys.openpgp.org/vks/v1/by-email/{email}'
        ),
        // Request timeout in seconds. Kept aggressive because the call
        // runs inside the MessageSending listener and blocks the send.
        'timeout' => (int) env('PGP_MAIL_KEYSERVER_TIMEOUT', 3),
        // When true, fetched keys are persisted via PgpKey::store() so
        // PgpKeyAdded/Rotated fire and the next send hits the local DB.
        'persist' => (bool) env('PGP_MAIL_KEYSERVER_PERSIST', true),
        // When true, the HTTP client verifies the server's TLS certificate.
        // Do not disable for production traffic.
        'verify_tls' => (bool) env('PGP_MAIL_KEYSERVER_VERIFY_TLS', true),
        // Sent as the User-Agent header.
        'user_agent' => env('PGP_MAIL_KEYSERVER_UA', 'laravel-pgp-mailer'),
        // Negative-cache TTL in seconds. After a miss, the resolver
        // remembers "no key" for this long instead of refetching on
        // every send. Set to 0 to disable.
        'negative_cache_ttl' => (int) env('PGP_MAIL_KEYSERVER_NEGATIVE_TTL', 3600),
        // Cache key prefix for the negative-result cache. Uses the same
        // store as `pgp-mailer.cache.store`.
        'cache_prefix' => env('PGP_MAIL_KEYSERVER_CACHE_PREFIX', 'pgp-mailer:ks-miss:'),
        // Cache key prefix for the per-email fetch lock. Required for
        // concurrent-worker coalescing; the configured cache store must
        // implement the atomic-lock contract (redis, memcached, database
        // — array works for single-process tests).
        'lock_prefix' => env('PGP_MAIL_KEYSERVER_LOCK_PREFIX', 'pgp-mailer:ks-fetch:'),
    ],

    /*
    | Protected Headers (encrypted Subject line).
    |
    | When enabled, the listener copies the outer Subject into the inner
    | encrypted-or-signed MIME part and replaces the outer Subject with
    | `placeholder_subject` before the message goes on the wire. The inner
    | part is marked with `Content-Type: ...; protected-headers="v1"` per
    | draft-ietf-lamps-header-protection AND carries the legacy memory-hole
    | `Subject:` header, so both modern MUAs (Thunderbird, recent Apple
    | Mail) and legacy ones (ProtonMail, K-9) display the real Subject
    | after decryption. MUAs that recognize neither show the placeholder
    | in their inbox list but still decrypt the body normally.
    |
    | Trade-offs to consider before flipping this on:
    |   - Threading by Subject collapses for non-supporting MUAs (modern
    |     MUAs thread by Message-ID/In-Reply-To and are unaffected).
    |   - Server-side subject search (Gmail web, etc.) becomes impossible.
    |
    | Per-message opt-out via the X-Pgp-Mailer-Visible-Subject header on
    | the Mailable (or {@see PgpMailer::withVisibleSubject()}) keeps the
    | outer Subject visible for that specific send.
    */
    'protected_headers' => [
        // Master switch. Default off — flipping this on changes how
        // outer Subject lines appear to every recipient, including the
        // ones whose MUA doesn't support protected headers.
        'enabled' => env('PGP_MAIL_PROTECTED_HEADERS', false),
        // What the outer Subject is rewritten to when protection is
        // applied. Matches ProtonMail's default for cross-MUA familiarity.
        'placeholder_subject' => env('PGP_MAIL_PROTECTED_HEADERS_PLACEHOLDER', 'Encrypted Subject'),
    ],

    // When true, PgpKey::store() rejects keys whose UID does not contain
    // the email it's being stored under. Disable only for fixtures or
    // legacy keys that pre-date the email-on-UID convention.
    'require_uid_match' => true,

    // Resolver-level filters applied when a stored key is fetched. Default
    // is to refuse using a key once it's expired or has been revoked — the
    // alternative would be silently encrypting to a dead key.
    'expiry' => [
        // Skip keys whose primary or encryption subkey is past its expiry.
        'reject_expired' => true,
        // Skip keys whose primary key has been revoked.
        'reject_revoked' => true,
    ],

    // Log channel for warnings emitted by missing-key / engine-failure
    // policies. Null uses the application's default channel.
    'log_channel' => env('PGP_MAIL_LOG_CHANNEL'),

];
