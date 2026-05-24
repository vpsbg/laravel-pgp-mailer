<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Engines;

/**
 * Public-key algorithm IDs → short human-readable names.
 *
 * Accepts both RFC 4880 §9.1 IDs (1–22) and GpgME extended IDs (301/302/303
 * for ECDSA/ECDH/EDDSA), because different gnupg PECL builds report ECC
 * algorithms under different schemes.
 */
final class OpenPgpAlgorithmMap
{
    /** @var array<int, string> */
    public const NAMES = [
        1 => 'rsa',
        2 => 'rsa-encrypt',
        3 => 'rsa-sign',
        16 => 'elgamal',
        17 => 'dsa',
        18 => 'ecdh',
        19 => 'ecdsa',
        22 => 'eddsa',
        301 => 'ecdsa',
        302 => 'ecdh',
        303 => 'eddsa',
    ];

    /**
     * Bit-length is appended for RSA only; for ECC the curve implies the
     * strength, so a number would be misleading.
     */
    public static function name(int $algorithm, ?int $bitLength = null): string
    {
        $name = self::NAMES[$algorithm] ?? 'algo-'.$algorithm;

        $isRsa = in_array($algorithm, [1, 2, 3], true);
        if ($isRsa && $bitLength !== null && $bitLength > 0) {
            return $name.$bitLength;
        }

        return $name;
    }
}
