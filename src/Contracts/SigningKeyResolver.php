<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Contracts;

use Vpsbg\PgpMailer\Exceptions\MissingSenderKeyException;
use Vpsbg\PgpMailer\Support\SigningKey;

interface SigningKeyResolver
{
    /**
     * Resolve the signing key to use for a given sender (From) address.
     *
     * Implementations MUST return the per-sender key when one is configured
     * for the exact (case-insensitive) address. When no per-sender match
     * exists, the implementation applies the configured policy:
     *
     *   - UseDefault — return the host-wide default signing key, or null
     *                  if no default is configured.
     *   - Skip       — return null. The listener will skip signing for
     *                  this message.
     *   - Fail       — throw {@see MissingSenderKeyException}.
     *
     * The $fromAddress parameter is null when the outbound message carries
     * no From header at all; implementations should treat that the same as
     * "no per-sender match" and apply the policy.
     */
    public function forSender(?string $fromAddress): ?SigningKey;
}
