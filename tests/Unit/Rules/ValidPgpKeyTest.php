<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Validator;
use Vpsbg\PgpMailer\Engines\GnupgExtensionEngine;
use Vpsbg\PgpMailer\Rules\ValidPgpKey;
use Vpsbg\PgpMailer\Support\ArmoredKey;
use Vpsbg\PgpMailer\Support\Fingerprint;

beforeEach(function (): void {
    $this->fixtures = $this->fixtureKeys();
    $this->email = $this->fixtureEmail();
});

function validateKey(string $value, ValidPgpKey $rule): Illuminate\Contracts\Validation\Validator
{
    return Validator::make(['key' => $value], ['key' => [$rule]]);
}

/**
 * Bind a stub engine that returns a hand-crafted ArmoredKey, so we can exercise
 * post-parse branches (expired, revoked, no-uid) without minting fresh fixtures.
 */
function bindStubEngine(ArmoredKey $canned): void
{
    app()->instance(GnupgExtensionEngine::class, new class($canned) extends GnupgExtensionEngine
    {
        public function __construct(private readonly ArmoredKey $canned)
        {
            parent::__construct();
        }

        public function parsePublicKey(string $armored): ArmoredKey
        {
            return $this->canned;
        }
    });
}

function cannedKey(array $overrides = []): ArmoredKey
{
    return new ArmoredKey(
        armored: $overrides['armored'] ?? '-----BEGIN PGP PUBLIC KEY BLOCK-----stub-----END PGP PUBLIC KEY BLOCK-----',
        fingerprint: $overrides['fingerprint'] ?? Fingerprint::fromHex(str_repeat('A', 40)),
        uids: $overrides['uids'] ?? ['Stub <stub@example.com>'],
        algorithm: $overrides['algorithm'] ?? 'rsa2048',
        createdAt: $overrides['createdAt'] ?? new DateTimeImmutable('2020-01-01'),
        expiresAt: $overrides['expiresAt'] ?? null,
        revoked: $overrides['revoked'] ?? false,
    );
}

it('passes for a well-formed fixture public key', function (): void {
    $v = validateKey($this->fixtures['public'], new ValidPgpKey);

    expect($v->passes())->toBeTrue();
});

it('skips empty values — pair with `required` to enforce presence', function (): void {
    // Laravel convention: a non-implicit rule does not run on empty values,
    // leaving that responsibility to `required`. Verify the convention holds.
    $v = validateKey('', new ValidPgpKey);

    expect($v->passes())->toBeTrue();
});

it('fails when the value is a non-string scalar', function (): void {
    $v = Validator::make(['key' => 12345], ['key' => [new ValidPgpKey]]);

    expect($v->fails())->toBeTrue();
    expect($v->errors()->first('key'))->toContain('not a valid OpenPGP public key');
});

it('fails for malformed armor', function (): void {
    $v = validateKey('not an armored block', new ValidPgpKey);

    expect($v->fails())->toBeTrue();
    expect($v->errors()->first('key'))->toContain('not a valid OpenPGP public key');
});

it('refuses a PRIVATE key block by default', function (): void {
    $v = validateKey($this->fixtures['private'], new ValidPgpKey);

    expect($v->fails())->toBeTrue();
    expect($v->errors()->first('key'))->toContain('PRIVATE key');
});

it('accepts a PRIVATE key block when ->allowSecretBlock() is set', function (): void {
    // The fixture private block parses as a valid key — gnupg accepts it.
    $v = validateKey($this->fixtures['private'], (new ValidPgpKey)->allowSecretBlock());

    expect($v->passes())->toBeTrue();
});

it('flags an expired key by default', function (): void {
    bindStubEngine(cannedKey(['expiresAt' => new DateTimeImmutable('2020-01-01')]));

    $v = validateKey($this->fixtures['public'], new ValidPgpKey);

    expect($v->fails())->toBeTrue();
    expect($v->errors()->first('key'))->toContain('expired');
});

it('accepts an expired key when ->allowExpired() is set', function (): void {
    bindStubEngine(cannedKey(['expiresAt' => new DateTimeImmutable('2020-01-01')]));

    $v = validateKey($this->fixtures['public'], (new ValidPgpKey)->allowExpired());

    expect($v->passes())->toBeTrue();
});

it('flags a revoked key by default', function (): void {
    bindStubEngine(cannedKey(['revoked' => true]));

    $v = validateKey($this->fixtures['public'], new ValidPgpKey);

    expect($v->fails())->toBeTrue();
    expect($v->errors()->first('key'))->toContain('revoked');
});

it('accepts a revoked key when ->allowRevoked() is set', function (): void {
    bindStubEngine(cannedKey(['revoked' => true]));

    $v = validateKey($this->fixtures['public'], (new ValidPgpKey)->allowRevoked());

    expect($v->passes())->toBeTrue();
});

it('flags a key with no usable UID', function (): void {
    bindStubEngine(cannedKey(['uids' => []]));

    $v = validateKey($this->fixtures['public'], new ValidPgpKey);

    expect($v->fails())->toBeTrue();
    expect($v->errors()->first('key'))->toContain('no usable user identifier');
});

it('enforces UID match when require_uid_match=true and ->forEmail() is set', function (): void {
    config()->set('pgp-mailer.require_uid_match', true);

    $v = validateKey($this->fixtures['public'], (new ValidPgpKey)->forEmail($this->email));
    expect($v->passes())->toBeTrue();

    $v = validateKey($this->fixtures['public'], (new ValidPgpKey)->forEmail('mismatch@example.com'));
    expect($v->fails())->toBeTrue();
    expect($v->errors()->first('key'))->toContain('UID matching');
});

it('skips UID match when require_uid_match=false even with ->forEmail()', function (): void {
    config()->set('pgp-mailer.require_uid_match', false);

    $v = validateKey($this->fixtures['public'], (new ValidPgpKey)->forEmail('mismatch@example.com'));

    expect($v->passes())->toBeTrue();
});

it('skips UID match when ->forEmail() is not called', function (): void {
    config()->set('pgp-mailer.require_uid_match', true);

    $v = validateKey($this->fixtures['public'], new ValidPgpKey);

    expect($v->passes())->toBeTrue();
});
