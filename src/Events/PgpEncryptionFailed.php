<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Events;

use Throwable;

final readonly class PgpEncryptionFailed
{
    /** @param  list<string>  $recipients */
    public function __construct(
        public array $recipients,
        public Throwable $reason,
    ) {}
}
