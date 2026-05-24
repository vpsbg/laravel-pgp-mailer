<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Casts\Attribute;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Vpsbg\PgpMailer\Database\Factories\PgpKeyFactory;
use Vpsbg\PgpMailer\Engines\GnupgExtensionEngine;
use Vpsbg\PgpMailer\Events\PgpKeyAdded;
use Vpsbg\PgpMailer\Events\PgpKeyRemoved;
use Vpsbg\PgpMailer\Events\PgpKeyRotated;
use Vpsbg\PgpMailer\Events\PgpKeyUidMismatch;
use Vpsbg\PgpMailer\Events\PgpKeyUidRefreshed;
use Vpsbg\PgpMailer\Exceptions\KeyParsingException;
use Vpsbg\PgpMailer\Support\Fingerprint;

/**
 * @property int $id
 * @property string $email
 * @property string $public_key
 * @property string $fingerprint
 * @property string|null $algorithm
 * @property Carbon|null $key_created_at
 * @property Carbon|null $expires_at
 * @property Carbon|null $revoked_at
 * @property Carbon|null $last_verified_at
 * @property Carbon|null $uid_mismatch_at
 */
class PgpKey extends Model
{
    /** @use HasFactory<PgpKeyFactory> */
    use HasFactory;

    protected $fillable = [
        'email',
        'public_key',
        'fingerprint',
        'algorithm',
        'key_created_at',
        'expires_at',
        'revoked_at',
        'last_verified_at',
        'uid_mismatch_at',
    ];

    protected $casts = [
        'key_created_at' => 'datetime',
        'expires_at' => 'datetime',
        'revoked_at' => 'datetime',
        'last_verified_at' => 'datetime',
        'uid_mismatch_at' => 'datetime',
    ];

    public function getTable(): string
    {
        return $this->table ?? (string) config('pgp-mailer.table', 'pgp_keys');
    }

    /** @return Attribute<string, string> */
    protected function email(): Attribute
    {
        return Attribute::make(
            set: fn (string $value): string => strtolower(trim($value)),
        );
    }

    /**
     * @param  Builder<self>  $query
     * @return Builder<self>
     */
    public function scopeForEmail(Builder $query, string $email): Builder
    {
        return $query->where('email', strtolower(trim($email)));
    }

    /**
     * @param  Builder<self>  $query
     * @return Builder<self>
     */
    public function scopeActive(Builder $query): Builder
    {
        $reject = config('pgp-mailer.expiry', []);

        if (($reject['reject_revoked'] ?? true) === true) {
            $query->whereNull('revoked_at');
        }

        if (($reject['reject_expired'] ?? true) === true) {
            $query->where(function (Builder $q): void {
                $q->whereNull('expires_at')->orWhere('expires_at', '>', now());
            });
        }

        return $query;
    }

    /**
     * Upsert a public key for an email address. Picks the right lifecycle event:
     * PgpKeyAdded for a fresh row, PgpKeyRotated when the fingerprint changes,
     * PgpKeyUidRefreshed when only the UID metadata refreshes after a prior mismatch.
     *
     * @throws KeyParsingException
     */
    public static function store(string $email, string $armoredPublicKey): static
    {
        $email = strtolower(trim($email));
        $engine = app(GnupgExtensionEngine::class);
        $parsed = $engine->parsePublicKey($armoredPublicKey);

        if ((bool) config('pgp-mailer.require_uid_match', true)
            && ! $parsed->hasUidMatching($email)) {
            throw (new KeyParsingException(
                'Public key does not include a UID matching '.$email.'.'
            ))->withRecipient($email)->withFingerprint($parsed->fingerprint);
        }

        if ($parsed->isExpired()) {
            throw (new KeyParsingException('Public key is expired.'))
                ->withRecipient($email)
                ->withFingerprint($parsed->fingerprint);
        }

        /** @var static|null $existing */
        $existing = static::query()->forEmail($email)->first();

        $attributes = [
            'email' => $email,
            'public_key' => $parsed->armored,
            'fingerprint' => (string) $parsed->fingerprint,
            'algorithm' => $parsed->algorithm,
            'key_created_at' => $parsed->createdAt,
            'expires_at' => $parsed->expiresAt,
            'revoked_at' => null,
            'last_verified_at' => now(),
        ];

        if ($existing === null) {
            /** @var static $key */
            $key = static::query()->create($attributes + ['uid_mismatch_at' => null]);
            Event::dispatch(new PgpKeyAdded($key));
            static::forgetCache($email);

            return $key;
        }

        $previousFingerprint = (string) $existing->fingerprint;
        $hadMismatch = $existing->uid_mismatch_at !== null;
        $sameFingerprint = strcasecmp($previousFingerprint, (string) $parsed->fingerprint) === 0;

        $existing->fill($attributes + ['uid_mismatch_at' => null])->save();

        if (! $sameFingerprint) {
            Event::dispatch(new PgpKeyRotated(
                key: $existing,
                previousFingerprint: Fingerprint::fromHex($previousFingerprint),
            ));
        } elseif ($hadMismatch) {
            Event::dispatch(new PgpKeyUidRefreshed($existing));
        }

        static::forgetCache($email);

        return $existing;
    }

    /**
     * Move a stored key from one email to another. Use this when an owning record's
     * email changes — typically from your own User::updating observer. When
     * $flagMismatch is true, sets uid_mismatch_at and dispatches PgpKeyUidMismatch so
     * the user can re-upload a key with the new address in its UID.
     */
    public static function transferEmail(string $oldEmail, string $newEmail, bool $flagMismatch = false): ?static
    {
        $oldEmail = strtolower(trim($oldEmail));
        $newEmail = strtolower(trim($newEmail));

        if ($oldEmail === '' || $oldEmail === $newEmail) {
            return null;
        }

        /** @var static|null $row */
        $row = static::query()->forEmail($oldEmail)->first();
        if ($row === null) {
            return null;
        }

        if ($flagMismatch) {
            $row->update(['email' => $newEmail, 'uid_mismatch_at' => now()]);
            Event::dispatch(new PgpKeyUidMismatch($row, $oldEmail, $newEmail));
        } else {
            $row->update(['email' => $newEmail, 'uid_mismatch_at' => null]);
        }

        static::forgetCache($oldEmail);
        static::forgetCache($newEmail);

        return $row;
    }

    /**
     * Delete the stored key for an email and dispatch PgpKeyRemoved. Returns
     * true when a row was removed.
     */
    public static function purgeEmail(string $email): bool
    {
        $email = strtolower(trim($email));

        /** @var static|null $row */
        $row = static::query()->forEmail($email)->first();
        if ($row === null) {
            return false;
        }

        $fingerprint = Fingerprint::fromHex((string) $row->fingerprint);
        $rowEmail = (string) $row->email;

        $row->delete();
        Event::dispatch(new PgpKeyRemoved($rowEmail, $fingerprint));
        static::forgetCache($email);

        return true;
    }

    protected static function forgetCache(string $email): void
    {
        if (! (bool) config('pgp-mailer.cache.enabled', true)) {
            return;
        }

        $prefix = (string) config('pgp-mailer.cache.prefix', 'pgp-mailer:key:');
        $store = config('pgp-mailer.cache.store');

        Cache::store($store)->forget($prefix.$email);
    }

    protected static function newFactory(): PgpKeyFactory
    {
        return PgpKeyFactory::new();
    }
}
