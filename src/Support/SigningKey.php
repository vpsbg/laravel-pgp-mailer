<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Support;

use Vpsbg\PgpMailer\Contracts\SigningKeyResolver;

/**
 * Value object carrying the credentials needed to sign a message with the
 * engine: an ASCII-armored private key block and an optional passphrase.
 *
 * Returned by {@see SigningKeyResolver}; consumed
 * by the listener when passing material into the engine's encrypt/sign
 * calls.
 */
final readonly class SigningKey
{
    public function __construct(
        public string $armored,
        public ?string $passphrase = null,
    ) {}
}
