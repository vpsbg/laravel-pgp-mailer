<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Support;

use DateTimeImmutable;
use DateTimeInterface;

final readonly class ArmoredKey
{
    /**
     * @param  list<string>  $uids  User IDs as raw RFC 4880 strings (e.g. "Alice <alice@example.com>").
     */
    public function __construct(
        public string $armored,
        public Fingerprint $fingerprint,
        public array $uids,
        public ?string $algorithm = null,
        public ?DateTimeImmutable $createdAt = null,
        public ?DateTimeImmutable $expiresAt = null,
        public bool $revoked = false,
        public bool $isPrivate = false,
    ) {}

    public function isExpired(?DateTimeInterface $now = null): bool
    {
        if ($this->expiresAt === null) {
            return false;
        }

        return ($now ?? new DateTimeImmutable) >= $this->expiresAt;
    }

    /** True if any UID's RFC 5322 address part matches $email (case-insensitive). */
    public function hasUidMatching(string $email): bool
    {
        $needle = strtolower(trim($email));

        foreach ($this->uids as $uid) {
            if ($needle === strtolower($this->extractEmailFromUid($uid))) {
                return true;
            }
        }

        return false;
    }

    /** Address part of "Name <addr@host>"; falls back to the UID itself. */
    private function extractEmailFromUid(string $uid): string
    {
        if (preg_match('/<([^>]+)>/', $uid, $m) === 1) {
            return trim($m[1]);
        }

        return trim($uid);
    }
}
