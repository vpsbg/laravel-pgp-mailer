<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Vpsbg\PgpMailer\Contracts\KeyResolver;
use Vpsbg\PgpMailer\Models\PgpKey;
use Vpsbg\PgpMailer\Resolvers\EloquentKeyResolver;

beforeEach(function (): void {
    $this->keys = $this->fixtureKeys();
    $this->resolver = $this->app->make(KeyResolver::class);

    expect($this->resolver)->toBeInstanceOf(EloquentKeyResolver::class);
});

it('resolves a stored key by exact email', function (): void {
    PgpKey::create([
        'email' => $this->fixtureEmail(),
        'public_key' => $this->keys['public'],
        'fingerprint' => str_repeat('A', 40),
    ]);

    $key = $this->resolver->forEmail($this->fixtureEmail());

    expect($key)->not->toBeNull();
    expect($key->fingerprint->longKeyId())->toBe('F6AD4E436EB07FD0');
});

it('is case-insensitive', function (): void {
    PgpKey::create([
        'email' => 'Alice@Example.Com',
        'public_key' => $this->keys['public'],
        'fingerprint' => str_repeat('A', 40),
    ]);

    expect($this->resolver->forEmail('ALICE@example.com'))->not->toBeNull();
});

it('excludes revoked keys', function (): void {
    PgpKey::create([
        'email' => $this->fixtureEmail(),
        'public_key' => $this->keys['public'],
        'fingerprint' => str_repeat('A', 40),
        'revoked_at' => now()->subDay(),
    ]);

    expect($this->resolver->forEmail($this->fixtureEmail()))->toBeNull();
});

it('excludes expired keys', function (): void {
    PgpKey::create([
        'email' => $this->fixtureEmail(),
        'public_key' => $this->keys['public'],
        'fingerprint' => str_repeat('A', 40),
        'expires_at' => now()->subDay(),
    ]);

    expect($this->resolver->forEmail($this->fixtureEmail()))->toBeNull();
});

it('returns null when no row matches', function (): void {
    expect($this->resolver->forEmail('nobody@example.com'))->toBeNull();
});

it('forEmails returns a map of resolved keys only', function (): void {
    PgpKey::create([
        'email' => 'alice@example.com',
        'public_key' => $this->keys['public'],
        'fingerprint' => str_repeat('A', 40),
    ]);
    PgpKey::create([
        'email' => 'bob@example.com',
        'public_key' => $this->keys['public'],
        'fingerprint' => str_repeat('B', 40),
    ]);

    $result = $this->resolver->forEmails(['alice@example.com', 'bob@example.com', 'charlie@example.com']);

    expect($result)->toHaveCount(2);
    expect(array_keys($result))->toContain('alice@example.com', 'bob@example.com');
    expect($result)->not->toHaveKey('charlie@example.com');
});

it('caches resolved keys and serves the second call from cache', function (): void {
    PgpKey::create([
        'email' => $this->fixtureEmail(),
        'public_key' => $this->keys['public'],
        'fingerprint' => str_repeat('A', 40),
    ]);

    $first = $this->resolver->forEmail($this->fixtureEmail());

    // Sabotage the DB: delete the row but keep the cache. Second call must still resolve.
    PgpKey::query()->delete();

    $second = $this->resolver->forEmail($this->fixtureEmail());

    expect($second)->not->toBeNull();
    expect((string) $second->fingerprint)->toBe((string) $first->fingerprint);
});

it('skips cache when disabled', function (): void {
    config()->set('pgp-mailer.cache.enabled', false);

    PgpKey::create([
        'email' => $this->fixtureEmail(),
        'public_key' => $this->keys['public'],
        'fingerprint' => str_repeat('A', 40),
    ]);

    $first = $this->resolver->forEmail($this->fixtureEmail());
    expect($first)->not->toBeNull();

    PgpKey::query()->delete();

    // With cache off, the second lookup must hit the (now-empty) DB.
    expect($this->resolver->forEmail($this->fixtureEmail()))->toBeNull();
});
