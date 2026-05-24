<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Events;

final readonly class PgpEncryptionApplied
{
    /**
     * @param  list<string>  $recipients  Lowercased email addresses the message was encrypted to.
     * @param  list<string>  $fingerprints  Long key IDs of the recipient keys used.
     */
    public function __construct(
        public array $recipients,
        public array $fingerprints,
        public bool $signed,
    ) {}
}
