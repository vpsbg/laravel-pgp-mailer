<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Events;

final readonly class PgpKeyserverFetchFailed
{
    /**
     * @param  string  $reason  One of: not_found, timeout, transport, parse_failed, uid_mismatch, expired.
     */
    public function __construct(
        public string $email,
        public string $reason,
        public ?int $httpStatus = null,
    ) {}
}
