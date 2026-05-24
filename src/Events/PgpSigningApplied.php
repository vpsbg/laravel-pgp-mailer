<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Events;

/**
 * Fired when the listener wraps a message in RFC 3156 multipart/signed
 * without encrypting it. Sibling of {@see PgpEncryptionApplied}; hosts that
 * want a unified "PGP applied" hook should listen for both.
 */
final readonly class PgpSigningApplied
{
    /**
     * @param  list<string>  $recipients  Lowercased recipient addresses on the signed message.
     */
    public function __construct(
        public array $recipients,
    ) {}
}
