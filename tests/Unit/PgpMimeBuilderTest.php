<?php

declare(strict_types=1);

use Vpsbg\PgpMailer\Mime\PgpCiphertextPart;
use Vpsbg\PgpMailer\Mime\PgpEncryptedPart;
use Vpsbg\PgpMailer\Mime\PgpMimeBuilder;
use Vpsbg\PgpMailer\Mime\PgpVersionPart;

it('wraps a ciphertext in the RFC 3156 envelope', function (): void {
    $cipher = "-----BEGIN PGP MESSAGE-----\n\nfake\n-----END PGP MESSAGE-----\n";
    $part = PgpMimeBuilder::wrap($cipher);

    expect($part)->toBeInstanceOf(PgpEncryptedPart::class);
    expect($part->getMediaType())->toBe('multipart');
    expect($part->getMediaSubtype())->toBe('encrypted');

    $serialized = $part->toString();
    expect($serialized)->toContain('multipart/encrypted');
    expect($serialized)->toContain('protocol="application/pgp-encrypted"');
    expect($serialized)->toContain('application/pgp-encrypted');
    expect($serialized)->toContain('Version: 1');
    expect($serialized)->toContain('application/octet-stream');
    expect($serialized)->toContain('-----BEGIN PGP MESSAGE-----');
});

it('emits the version part exactly as RFC 3156 §6 requires', function (): void {
    $version = new PgpVersionPart;
    $serialized = $version->toString();

    expect($serialized)->toContain('Content-Type: application/pgp-encrypted');
    expect($serialized)->toContain('Content-Transfer-Encoding: 7bit');
    expect($serialized)->toContain('Version: 1');
});

it('emits the ciphertext part with 7bit encoding and inline disposition', function (): void {
    $part = new PgpCiphertextPart("-----BEGIN PGP MESSAGE-----\nfoo\n-----END PGP MESSAGE-----\n");
    $serialized = $part->toString();

    expect($serialized)->toContain('Content-Type: application/octet-stream');
    expect($serialized)->toContain('Content-Transfer-Encoding: 7bit');
    expect($serialized)->toContain('Content-Disposition: inline');
    expect($serialized)->toContain('filename=encrypted.asc');
});
