<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Events;

use Vpsbg\PgpMailer\Models\PgpKey;

final readonly class PgpKeyUidRefreshed
{
    public function __construct(public PgpKey $key) {}
}
