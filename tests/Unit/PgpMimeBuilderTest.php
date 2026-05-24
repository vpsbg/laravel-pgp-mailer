<?php

declare(strict_types=1);

use Symfony\Component\Mime\Part\TextPart;
use Vpsbg\PgpMailer\Mime\PgpCiphertextPart;
use Vpsbg\PgpMailer\Mime\PgpEncryptedPart;
use Vpsbg\PgpMailer\Mime\PgpMimeBuilder;
use Vpsbg\PgpMailer\Mime\PgpSignedPart;
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

it('wraps a body and detached signature in the RFC 3156 multipart/signed envelope', function (): void {
    $body = new TextPart('hello world');
    $sig = "-----BEGIN PGP SIGNATURE-----\n\nfake\n-----END PGP SIGNATURE-----\n";

    $part = PgpMimeBuilder::wrapSigned($body, $sig);

    expect($part)->toBeInstanceOf(PgpSignedPart::class);
    expect($part->getMediaType())->toBe('multipart');
    expect($part->getMediaSubtype())->toBe('signed');

    $serialized = $part->toString();
    expect($serialized)->toContain('multipart/signed');
    expect($serialized)->toContain('protocol="application/pgp-signature"');
    expect($serialized)->toContain('micalg=pgp-sha256');
    expect($serialized)->toContain('hello world');
    expect($serialized)->toContain('application/pgp-signature');
    expect($serialized)->toContain('-----BEGIN PGP SIGNATURE-----');
});

it('lets the caller override micalg for non-SHA-256 signing keys', function (): void {
    $part = PgpMimeBuilder::wrapSigned(new TextPart('body'), 'sig-armor', micalg: 'pgp-sha512');

    expect($part->toString())->toContain('micalg=pgp-sha512');
});

it('preserves the signed body bytes between signing and serialization', function (): void {
    // The contract: the bytes we get from $body->toString() before signing
    // must equal the bytes that appear between the multipart boundaries on
    // the wire — otherwise the detached signature cannot verify.
    $body = new TextPart("line one\r\nline two\r\n");
    $beforeSigning = $body->toString();

    $part = PgpMimeBuilder::wrapSigned($body, 'sig');
    $serialized = $part->toString();

    expect($serialized)->toContain($beforeSigning);
});
