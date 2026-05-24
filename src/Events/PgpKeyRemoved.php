<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Events;

use Vpsbg\PgpMailer\Support\Fingerprint;

final readonly class PgpKeyRemoved
{
    public function __construct(
        public string $email,
        public Fingerprint $fingerprint,
    ) {}
}
