<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Support;

use InvalidArgumentException;
use Stringable;

final readonly class Fingerprint implements Stringable
{
    /** Uppercase hex, no separators. SHA-1 = 40 chars, SHA-256 = 64. */
    public string $hex;

    private function __construct(string $hex)
    {
        $this->hex = $hex;
    }

    public static function fromHex(string $hex): self
    {
        $normalized = strtoupper(preg_replace('/[^0-9a-fA-F]/', '', $hex) ?? '');

        if (! in_array(strlen($normalized), [40, 64], true)) {
            throw new InvalidArgumentException(
                'Fingerprint must be a 40- or 64-character hex string; got '.strlen($normalized)
            );
        }

        return new self($normalized);
    }

    public static function fromBinary(string $bytes): self
    {
        return self::fromHex(bin2hex($bytes));
    }

    /** Last 16 hex chars (last 8 bytes) — the conventional "long key id". */
    public function longKeyId(): string
    {
        return substr($this->hex, -16);
    }

    /** GPG-style display: 5 groups of 4 hex chars, space-separated, repeated. */
    public function display(): string
    {
        return trim(chunk_split($this->hex, 4, ' '));
    }

    public function equals(self $other): bool
    {
        return hash_equals($this->hex, $other->hex);
    }

    public function __toString(): string
    {
        return $this->hex;
    }
}
