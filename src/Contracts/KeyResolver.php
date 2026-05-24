<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Contracts;

use Vpsbg\PgpMailer\Support\ArmoredKey;

interface KeyResolver
{
    /**
     * Look up the active public key for a single email address.
     *
     * Implementations MUST exclude revoked and expired keys when the host has
     * `pgp-mailer.expiry.reject_*` enabled (the default).
     */
    public function forEmail(string $email): ?ArmoredKey;

    /**
     * Bulk variant. Returns a map of lowercased email → ArmoredKey for all
     * addresses that resolved. Addresses without a key are omitted from the map.
     *
     * @param  iterable<string>  $emails
     * @return array<string, ArmoredKey>
     */
    public function forEmails(iterable $emails): array;
}
