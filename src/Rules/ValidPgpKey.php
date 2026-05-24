<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Rules;

use Closure;
use Illuminate\Contracts\Validation\ValidationRule;
use Vpsbg\PgpMailer\Engines\GnupgExtensionEngine;
use Vpsbg\PgpMailer\Exceptions\KeyParsingException;

/**
 * Validates that a string field carries an importable ASCII-armored OpenPGP
 * public key. Wraps GnupgExtensionEngine::parsePublicKey() and translates its
 * outcomes into per-field validation failures so hosts can surface errors
 * alongside `required` / `string` / `max:N` in a single validator call.
 *
 * Defaults: rejects malformed armor, expired keys, revoked keys, secret/private
 * key blocks, and keys with no usable UID. UID-address match is enforced when
 * `pgp-mailer.require_uid_match` is true AND ->forEmail() was called with a
 * non-empty address.
 */
final class ValidPgpKey implements ValidationRule
{
    private ?string $expectedEmail = null;

    private bool $allowExpired = false;

    private bool $allowRevoked = false;

    private bool $allowSecretBlock = false;

    public function forEmail(?string $email): self
    {
        $email = $email === null ? null : trim($email);
        $this->expectedEmail = $email === '' ? null : $email;

        return $this;
    }

    public function allowExpired(bool $allow = true): self
    {
        $this->allowExpired = $allow;

        return $this;
    }

    public function allowRevoked(bool $allow = true): self
    {
        $this->allowRevoked = $allow;

        return $this;
    }

    public function allowSecretBlock(bool $allow = true): self
    {
        $this->allowSecretBlock = $allow;

        return $this;
    }

    public function validate(string $attribute, mixed $value, Closure $fail): void
    {
        if (! is_string($value) || trim($value) === '') {
            $this->raise($fail, $attribute, 'invalid_armor');

            return;
        }

        // Cheap pre-flight before importing into a scratch homedir: refuse
        // secret blocks outright unless the host has explicitly allowed them.
        if (! $this->allowSecretBlock && $this->looksLikeSecretBlock($value)) {
            $this->raise($fail, $attribute, 'secret_block');

            return;
        }

        try {
            $parsed = app(GnupgExtensionEngine::class)->parsePublicKey($value);
        } catch (KeyParsingException) {
            $this->raise($fail, $attribute, 'invalid_armor');

            return;
        }

        if ($parsed->revoked && ! $this->allowRevoked) {
            $this->raise($fail, $attribute, 'revoked');

            return;
        }

        if ($parsed->isExpired() && ! $this->allowExpired) {
            $this->raise($fail, $attribute, 'expired');

            return;
        }

        if ($parsed->uids === []) {
            $this->raise($fail, $attribute, 'no_usable_uid');

            return;
        }

        if ($this->expectedEmail !== null
            && (bool) config('pgp-mailer.require_uid_match', true)
            && ! $parsed->hasUidMatching($this->expectedEmail)) {
            $this->raise($fail, $attribute, 'uid_mismatch');
        }
    }

    private function raise(Closure $fail, string $attribute, string $key): void
    {
        $fail(__('pgp-mailer::validation.pgp_key.'.$key, ['attribute' => $attribute]));
    }

    private function looksLikeSecretBlock(string $value): bool
    {
        return preg_match('/-----BEGIN PGP PRIVATE KEY BLOCK-----/', $value) === 1;
    }
}
