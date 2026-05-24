<?php

declare(strict_types=1);

use Vpsbg\PgpMailer\Exceptions\MissingSenderKeyException;
use Vpsbg\PgpMailer\Resolvers\ConfigSigningKeyResolver;
use Vpsbg\PgpMailer\Support\SigningKey;

beforeEach(function (): void {
    config()->set('pgp-mailer.signing', [
        'enabled' => true,
        'key_path' => null,
        'key' => null,
        'passphrase' => null,
        'senders' => [],
        'unmatched_sender_policy' => 'use_default',
    ]);

    $this->resolver = app(ConfigSigningKeyResolver::class);
});

it('returns the per-sender key when the From address matches exactly', function (): void {
    config()->set('pgp-mailer.signing.senders', [
        'support@example.com' => [
            'key' => 'ARMOREDSUPPORTKEY',
            'passphrase' => 'support-pass',
        ],
    ]);

    $key = $this->resolver->forSender('support@example.com');

    expect($key)->toBeInstanceOf(SigningKey::class);
    expect($key->armored)->toBe('ARMOREDSUPPORTKEY');
    expect($key->passphrase)->toBe('support-pass');
});

it('matches sender addresses case-insensitively', function (): void {
    config()->set('pgp-mailer.signing.senders', [
        'Support@Example.com' => ['key' => 'CASEKEY'],
    ]);

    expect($this->resolver->forSender('support@example.com')?->armored)->toBe('CASEKEY');
    expect($this->resolver->forSender('SUPPORT@EXAMPLE.COM')?->armored)->toBe('CASEKEY');
});

it('falls back to the default scalar key under use_default policy', function (): void {
    config()->set('pgp-mailer.signing.key', 'ARMOREDDEFAULTKEY');
    config()->set('pgp-mailer.signing.passphrase', 'default-pass');
    config()->set('pgp-mailer.signing.unmatched_sender_policy', 'use_default');

    $key = $this->resolver->forSender('unknown@example.com');

    expect($key)->toBeInstanceOf(SigningKey::class);
    expect($key->armored)->toBe('ARMOREDDEFAULTKEY');
    expect($key->passphrase)->toBe('default-pass');
});

it('returns null under use_default when no default is configured', function (): void {
    config()->set('pgp-mailer.signing.unmatched_sender_policy', 'use_default');

    expect($this->resolver->forSender('unknown@example.com'))->toBeNull();
});

it('returns null under skip policy regardless of default', function (): void {
    config()->set('pgp-mailer.signing.key', 'ARMOREDDEFAULTKEY');
    config()->set('pgp-mailer.signing.unmatched_sender_policy', 'skip');

    expect($this->resolver->forSender('unknown@example.com'))->toBeNull();
});

it('throws MissingSenderKeyException under fail policy', function (): void {
    config()->set('pgp-mailer.signing.unmatched_sender_policy', 'fail');

    expect(fn () => $this->resolver->forSender('unknown@example.com'))
        ->toThrow(MissingSenderKeyException::class);
});

it('reads key material from key_path lazily', function (): void {
    $path = tempnam(sys_get_temp_dir(), 'pgp-signer-');
    file_put_contents($path, 'FILEKEYBYTES');

    try {
        config()->set('pgp-mailer.signing.senders', [
            'ops@example.com' => ['key_path' => $path, 'passphrase' => null],
        ]);

        $key = $this->resolver->forSender('ops@example.com');

        expect($key?->armored)->toBe('FILEKEYBYTES');
    } finally {
        @unlink($path);
    }
});

it('logs and returns null when a configured key_path is unreadable', function (): void {
    config()->set('pgp-mailer.signing.senders', [
        'ops@example.com' => ['key_path' => '/nonexistent/path/to/key.asc'],
    ]);
    // unmatched_sender_policy stays use_default with no default — we expect
    // the per-sender entry to be picked, then materialize to null, then the
    // policy to fall through to (null) default. Net result: null.

    expect($this->resolver->forSender('ops@example.com'))->toBeNull();
});

it('applies the unmatched policy when From is null (no From header)', function (): void {
    config()->set('pgp-mailer.signing.key', 'ARMOREDDEFAULTKEY');
    config()->set('pgp-mailer.signing.unmatched_sender_policy', 'use_default');

    expect($this->resolver->forSender(null)?->armored)->toBe('ARMOREDDEFAULTKEY');
});

it('prefers the per-sender entry over the scalar default when both are set', function (): void {
    config()->set('pgp-mailer.signing.key', 'ARMOREDDEFAULTKEY');
    config()->set('pgp-mailer.signing.senders', [
        'support@example.com' => ['key' => 'PERSENDERKEY'],
    ]);

    expect($this->resolver->forSender('support@example.com')?->armored)->toBe('PERSENDERKEY');
    expect($this->resolver->forSender('other@example.com')?->armored)->toBe('ARMOREDDEFAULTKEY');
});
