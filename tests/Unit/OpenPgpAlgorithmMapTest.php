<?php

declare(strict_types=1);

use Vpsbg\PgpMailer\Engines\OpenPgpAlgorithmMap;

it('maps RFC 4880 RSA ids to a name with bit-length suffix', function (): void {
    expect(OpenPgpAlgorithmMap::name(1, 2048))->toBe('rsa2048');
    expect(OpenPgpAlgorithmMap::name(1, 4096))->toBe('rsa4096');
    expect(OpenPgpAlgorithmMap::name(2, 2048))->toBe('rsa-encrypt2048');
    expect(OpenPgpAlgorithmMap::name(3, 2048))->toBe('rsa-sign2048');
});

it('maps RFC 4880 ECC ids to the bare curve name with NO bit-length', function (): void {
    // Bit-length on ECC is misleading — the curve implies the strength —
    // and gets silently dropped by the helper.
    expect(OpenPgpAlgorithmMap::name(18, 256))->toBe('ecdh');
    expect(OpenPgpAlgorithmMap::name(19, 256))->toBe('ecdsa');
    expect(OpenPgpAlgorithmMap::name(22, 256))->toBe('eddsa');
});

it('maps GpgME extended ids (301/302/303) to the same names as their RFC counterparts', function (): void {
    // Some builds of the gnupg PECL extension report 301/302/303 (gpgme.h
    // GPGME_PK_ECDSA/ECDH/EDDSA) instead of RFC 19/18/22. The output string
    // must be the same so pgp_keys.algorithm reads identically regardless
    // of which engine parsed the key.
    expect(OpenPgpAlgorithmMap::name(301))->toBe('ecdsa');
    expect(OpenPgpAlgorithmMap::name(302))->toBe('ecdh');
    expect(OpenPgpAlgorithmMap::name(303))->toBe('eddsa');
});

it('returns a sentinel for unknown ids instead of throwing', function (): void {
    expect(OpenPgpAlgorithmMap::name(999))->toBe('algo-999');
});
