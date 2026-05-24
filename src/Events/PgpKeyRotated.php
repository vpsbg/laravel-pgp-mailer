<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Events;

use Vpsbg\PgpMailer\Models\PgpKey;
use Vpsbg\PgpMailer\Support\Fingerprint;

final readonly class PgpKeyRotated
{
    public function __construct(
        public PgpKey $key,
        public Fingerprint $previousFingerprint,
    ) {}
}
