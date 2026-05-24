<?php

declare(strict_types=1);

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Vpsbg\PgpMailer\Contracts\KeyResolver;
use Vpsbg\PgpMailer\Events\PgpKeyserverFetchFailed;
use Vpsbg\PgpMailer\Events\PgpKeyserverFetchSucceeded;
use Vpsbg\PgpMailer\Models\PgpKey;
use Vpsbg\PgpMailer\Resolvers\KeyserverKeyResolver;

beforeEach(function (): void {
    config()->set('pgp-mailer.keyserver.enabled', true);
    config()->set('pgp-mailer.keyserver.url_template', 'https://keys.test/by-email/{email}');
    config()->set('pgp-mailer.keyserver.timeout', 3);
    config()->set('pgp-mailer.keyserver.persist', true);
    config()->set('pgp-mailer.keyserver.verify_tls', true);
    config()->set('pgp-mailer.keyserver.negative_cache_ttl', 3600);
    config()->set('pgp-mailer.keyserver.cache_prefix', 'pgp-mailer:ks-miss:');

    $this->keys = $this->fixtureKeys();
    $this->email = $this->fixtureEmail();

    // Build the resolver fresh on each test AFTER any Event::fake() the test
    // sets up — the resolver captures the Dispatcher by reference at
    // construction time.
    $this->makeResolver = fn (): KeyserverKeyResolver => $this->app->make(KeyserverKeyResolver::class);
});

it('fetches, parses, persists, and dispatches success on a 200 response', function (): void {
    Event::fake([PgpKeyserverFetchSucceeded::class, PgpKeyserverFetchFailed::class]);
    Http::fake([
        'keys.test/by-email/*' => Http::response($this->keys['public'], 200),
    ]);

    $key = ($this->makeResolver)()->forEmail($this->email);

    expect($key)->not->toBeNull();
    expect($key->fingerprint->longKeyId())->toBe('F6AD4E436EB07FD0');
    expect(PgpKey::query()->forEmail($this->email)->exists())->toBeTrue();

    Event::assertDispatched(PgpKeyserverFetchSucceeded::class, fn ($e): bool => $e->email === $this->email && $e->persisted === true);
    Event::assertNotDispatched(PgpKeyserverFetchFailed::class);
});

it('does not persist when persist=false', function (): void {
    config()->set('pgp-mailer.keyserver.persist', false);
    Event::fake([PgpKeyserverFetchSucceeded::class]);
    Http::fake([
        'keys.test/by-email/*' => Http::response($this->keys['public'], 200),
    ]);

    $key = ($this->makeResolver)()->forEmail($this->email);

    expect($key)->not->toBeNull();
    expect(PgpKey::query()->forEmail($this->email)->exists())->toBeFalse();

    Event::assertDispatched(PgpKeyserverFetchSucceeded::class, fn ($e): bool => $e->persisted === false);
});

it('returns null on 404 and dispatches not_found', function (): void {
    Event::fake([PgpKeyserverFetchFailed::class]);
    Http::fake([
        'keys.test/by-email/*' => Http::response('', 404),
    ]);

    $key = ($this->makeResolver)()->forEmail('nobody@example.com');

    expect($key)->toBeNull();
    expect(Cache::has('pgp-mailer:ks-miss:nobody@example.com'))->toBeTrue();

    Event::assertDispatched(PgpKeyserverFetchFailed::class, fn ($e): bool => $e->reason === 'not_found' && $e->httpStatus === 404);
});

it('returns null on a connection timeout and dispatches timeout', function (): void {
    Event::fake([PgpKeyserverFetchFailed::class]);
    Http::fake(function (): never {
        throw new ConnectionException('cURL error 28: Operation timed out after 3000 milliseconds');
    });

    $key = ($this->makeResolver)()->forEmail($this->email);

    expect($key)->toBeNull();
    Event::assertDispatched(PgpKeyserverFetchFailed::class, fn ($e): bool => $e->reason === 'timeout');
});

it('returns null on a transport error', function (): void {
    Event::fake([PgpKeyserverFetchFailed::class]);
    Http::fake(function (): never {
        throw new ConnectionException('cURL error 6: Could not resolve host');
    });

    $key = ($this->makeResolver)()->forEmail($this->email);

    expect($key)->toBeNull();
    Event::assertDispatched(PgpKeyserverFetchFailed::class, fn ($e): bool => $e->reason === 'transport');
});

it('returns null when the response body is not a parseable PGP key', function (): void {
    Event::fake([PgpKeyserverFetchFailed::class]);
    Http::fake([
        'keys.test/by-email/*' => Http::response('not a pgp key', 200),
    ]);

    $key = ($this->makeResolver)()->forEmail($this->email);

    expect($key)->toBeNull();
    Event::assertDispatched(PgpKeyserverFetchFailed::class, fn ($e): bool => $e->reason === 'parse_failed');
});

it('returns null when the fetched key UID does not match and require_uid_match is true', function (): void {
    config()->set('pgp-mailer.require_uid_match', true);
    Event::fake([PgpKeyserverFetchFailed::class]);
    Http::fake([
        'keys.test/by-email/*' => Http::response($this->keys['public'], 200),
    ]);

    // Recipient email differs from the fixture key's UID (gnupg-smoke@test.local).
    $key = ($this->makeResolver)()->forEmail('imposter@example.com');

    expect($key)->toBeNull();
    expect(PgpKey::query()->forEmail('imposter@example.com')->exists())->toBeFalse();
    Event::assertDispatched(PgpKeyserverFetchFailed::class, fn ($e): bool => $e->reason === 'uid_mismatch');
});

it('rejects a UID-mismatched key even when persist=false', function (): void {
    config()->set('pgp-mailer.require_uid_match', true);
    config()->set('pgp-mailer.keyserver.persist', false);
    Event::fake([PgpKeyserverFetchFailed::class, PgpKeyserverFetchSucceeded::class]);
    Http::fake([
        'keys.test/by-email/*' => Http::response($this->keys['public'], 200),
    ]);

    $key = ($this->makeResolver)()->forEmail('imposter@example.com');

    expect($key)->toBeNull();
    Event::assertDispatched(PgpKeyserverFetchFailed::class, fn ($e): bool => $e->reason === 'uid_mismatch');
    Event::assertNotDispatched(PgpKeyserverFetchSucceeded::class);
});

it('honors the negative cache and does not re-fetch on a second call', function (): void {
    Event::fake([PgpKeyserverFetchFailed::class]);
    Http::fake([
        'keys.test/by-email/*' => Http::response('', 404),
    ]);

    ($this->makeResolver)()->forEmail('nobody@example.com');
    ($this->makeResolver)()->forEmail('nobody@example.com');

    Http::assertSentCount(1);
});

it('builds the URL by URL-encoding the email into the {email} placeholder', function (): void {
    Http::fake([
        'keys.test/by-email/*' => Http::response($this->keys['public'], 200),
    ]);

    ($this->makeResolver)()->forEmail($this->email);

    Http::assertSent(fn ($request): bool => $request->url() === 'https://keys.test/by-email/'.rawurlencode($this->email));
});

it('returns nothing and short-circuits when the negative cache TTL is zero', function (): void {
    config()->set('pgp-mailer.keyserver.negative_cache_ttl', 0);
    Http::fake([
        'keys.test/by-email/*' => Http::response('', 404),
    ]);

    ($this->makeResolver)()->forEmail('nobody@example.com');
    ($this->makeResolver)()->forEmail('nobody@example.com');

    Http::assertSentCount(2);
    expect(Cache::has('pgp-mailer:ks-miss:nobody@example.com'))->toBeFalse();
});

it('uses the configured User-Agent header', function (): void {
    config()->set('pgp-mailer.keyserver.user_agent', 'custom-ua/1.0');
    Http::fake([
        'keys.test/by-email/*' => Http::response($this->keys['public'], 200),
    ]);

    ($this->makeResolver)()->forEmail($this->email);

    Http::assertSent(fn ($request): bool => $request->header('User-Agent') === ['custom-ua/1.0']);
});

it('is wired into the resolver chain when keyserver.enabled is true', function (): void {
    Http::fake([
        'keys.test/by-email/*' => Http::response($this->keys['public'], 200),
    ]);

    // The KeyResolver binding is a chain when enabled — request through the
    // contract to confirm the wiring, not just the standalone class.
    $resolver = $this->app->make(KeyResolver::class);

    $key = $resolver->forEmail($this->email);

    expect($key)->not->toBeNull();
});
