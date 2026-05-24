<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Events;

use Vpsbg\PgpMailer\Models\PgpKey;

final readonly class PgpKeyAdded
{
    public function __construct(public PgpKey $key) {}
}
