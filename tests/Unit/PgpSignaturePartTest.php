<?php

declare(strict_types=1);

use Vpsbg\PgpMailer\Mime\PgpSignaturePart;

it('emits an application/pgp-signature part with 7bit encoding and signature.asc filename', function (): void {
    $armor = "-----BEGIN PGP SIGNATURE-----\n\nfake\n-----END PGP SIGNATURE-----\n";
    $part = new PgpSignaturePart($armor);

    $serialized = $part->toString();

    expect($serialized)->toContain('Content-Type: application/pgp-signature');
    expect($serialized)->toContain('Content-Transfer-Encoding: 7bit');
    expect($serialized)->toContain('Content-Description: OpenPGP digital signature');
    expect($serialized)->toContain('Content-Disposition: attachment');
    expect($serialized)->toContain('filename=signature.asc');
    expect($serialized)->toContain('-----BEGIN PGP SIGNATURE-----');
});

it('reports the media type pair as application/pgp-signature', function (): void {
    $part = new PgpSignaturePart('whatever');

    expect($part->getMediaType())->toBe('application');
    expect($part->getMediaSubtype())->toBe('pgp-signature');
});
