<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Events;

use Vpsbg\PgpMailer\Models\PgpKey;

final readonly class PgpKeyUidMismatch
{
    public function __construct(
        public PgpKey $key,
        public string $previousEmail,
        public string $newEmail,
    ) {}
}
