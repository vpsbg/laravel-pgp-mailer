<?php

declare(strict_types=1);

use Vpsbg\PgpMailer\Support\Fingerprint;

it('normalizes mixed casing and separators', function (): void {
    $fp = Fingerprint::fromHex('5c 86 e8 ef cd 94 6f 05 fd cc 99 a3 f6 ad 4e 43 6e b0 7f d0');

    expect((string) $fp)->toBe('5C86E8EFCD946F05FDCC99A3F6AD4E436EB07FD0');
});

it('rejects too-short input', function (): void {
    Fingerprint::fromHex('deadbeef');
})->throws(InvalidArgumentException::class);

it('accepts SHA-256 (64-char) fingerprints', function (): void {
    $hex = str_repeat('a', 64);

    expect((string) Fingerprint::fromHex($hex))
        ->toBe(strtoupper($hex));
});

it('exposes the long key id', function (): void {
    expect(Fingerprint::fromHex('5C86E8EFCD946F05FDCC99A3F6AD4E436EB07FD0')->longKeyId())
        ->toBe('F6AD4E436EB07FD0');
});

it('formats the display form in 5-char groups', function (): void {
    expect(Fingerprint::fromHex('5C86E8EFCD946F05FDCC99A3F6AD4E436EB07FD0')->display())
        ->toBe('5C86 E8EF CD94 6F05 FDCC 99A3 F6AD 4E43 6EB0 7FD0');
});

it('compares using hash_equals', function (): void {
    $a = Fingerprint::fromHex('5C86E8EFCD946F05FDCC99A3F6AD4E436EB07FD0');
    $b = Fingerprint::fromHex('5c86e8efcd946f05fdcc99a3f6ad4e436eb07fd0');
    $c = Fingerprint::fromHex(str_repeat('0', 40));

    expect($a->equals($b))->toBeTrue();
    expect($a->equals($c))->toBeFalse();
});
