<?php

declare(strict_types=1);

use Vpsbg\PgpMailer\Engines\GnupgExtensionEngine;
use Vpsbg\PgpMailer\Exceptions\KeyParsingException;
use Vpsbg\PgpMailer\Support\ArmoredKey;

beforeEach(function (): void {
    $this->engine = new GnupgExtensionEngine;
    $this->armoredPublic = file_get_contents(__DIR__.'/../fixtures/pgp/recipient-public.asc');
});

it('parses the fixture public key', function (): void {
    $key = $this->engine->parsePublicKey($this->armoredPublic);

    expect($key->fingerprint->longKeyId())->toBe('F6AD4E436EB07FD0');
    expect($key->algorithm)->toBe('rsa2048');
    expect($key->uids)->toBe(['Gnupg Smoke <gnupg-smoke@test.local>']);
    expect($key->createdAt)->not->toBeNull();
});

it('matches its own UID address case-insensitively', function (): void {
    $key = $this->engine->parsePublicKey($this->armoredPublic);

    expect($key->hasUidMatching('gnupg-smoke@test.local'))->toBeTrue();
    expect($key->hasUidMatching('GNUPG-SMOKE@TEST.LOCAL'))->toBeTrue();
    expect($key->hasUidMatching(' gnupg-smoke@test.local '))->toBeTrue();
    expect($key->hasUidMatching('other@test.local'))->toBeFalse();
});

it('reports unexpired when the fixture has no expiry', function (): void {
    $key = $this->engine->parsePublicKey($this->armoredPublic);

    expect($key->isExpired())->toBeFalse();
});

it('reports expired when a synthetic expiresAt is in the past', function (): void {
    $key = $this->engine->parsePublicKey($this->armoredPublic);

    $expired = new ArmoredKey(
        armored: $key->armored,
        fingerprint: $key->fingerprint,
        uids: $key->uids,
        algorithm: $key->algorithm,
        createdAt: $key->createdAt,
        expiresAt: new DateTimeImmutable('2020-01-01'),
    );

    expect($expired->isExpired())->toBeTrue();
});

it('rejects malformed armor', function (): void {
    $this->engine->parsePublicKey('not an armored block');
})->throws(KeyParsingException::class);
