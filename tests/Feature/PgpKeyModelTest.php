<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Event;
use Vpsbg\PgpMailer\Contracts\KeyResolver;
use Vpsbg\PgpMailer\Events\PgpKeyAdded;
use Vpsbg\PgpMailer\Events\PgpKeyRemoved;
use Vpsbg\PgpMailer\Events\PgpKeyRotated;
use Vpsbg\PgpMailer\Events\PgpKeyUidMismatch;
use Vpsbg\PgpMailer\Events\PgpKeyUidRefreshed;
use Vpsbg\PgpMailer\Exceptions\KeyParsingException;
use Vpsbg\PgpMailer\Models\PgpKey;

beforeEach(function (): void {
    $this->keys = $this->fixtureKeys();
    $this->email = $this->fixtureEmail();
});

it('store() creates a row and dispatches PgpKeyAdded', function (): void {
    Event::fake();

    $key = PgpKey::store($this->email, $this->keys['public']);

    expect($key)->toBeInstanceOf(PgpKey::class);
    expect($key->email)->toBe($this->email);
    expect($key->fingerprint)->toEndWith('F6AD4E436EB07FD0');
    expect($key->algorithm)->toBe('rsa2048');

    Event::assertDispatched(PgpKeyAdded::class);
    Event::assertNotDispatched(PgpKeyRotated::class);
    Event::assertNotDispatched(PgpKeyUidRefreshed::class);
});

it('store() rejects keys whose UID does not match the email', function (): void {
    PgpKey::store('mallory@example.com', $this->keys['public']);
})->throws(KeyParsingException::class, 'UID matching');

it('store() accepts UID mismatch when require_uid_match is false', function (): void {
    config()->set('pgp-mailer.require_uid_match', false);

    $key = PgpKey::store('mallory@example.com', $this->keys['public']);

    expect($key->email)->toBe('mallory@example.com');
});

it('re-storing the same fingerprint is a silent no-op when no prior mismatch', function (): void {
    PgpKey::store($this->email, $this->keys['public']);

    Event::fake();
    PgpKey::store($this->email, $this->keys['public']);

    Event::assertNotDispatched(PgpKeyAdded::class);
    Event::assertNotDispatched(PgpKeyRotated::class);
    Event::assertNotDispatched(PgpKeyUidRefreshed::class);
});

it('re-storing the same fingerprint emits PgpKeyUidRefreshed when uid_mismatch_at was set', function (): void {
    $row = PgpKey::store($this->email, $this->keys['public']);
    $row->update(['uid_mismatch_at' => now()]);

    Event::fake([PgpKeyUidRefreshed::class, PgpKeyRotated::class]);
    PgpKey::store($this->email, $this->keys['public']);

    Event::assertDispatched(PgpKeyUidRefreshed::class);
    Event::assertNotDispatched(PgpKeyRotated::class);

    expect(PgpKey::query()->first()->uid_mismatch_at)->toBeNull();
});

it('store() invalidates the resolver cache', function (): void {
    $resolver = app(KeyResolver::class);
    expect($resolver->forEmail($this->email))->toBeNull();

    PgpKey::store($this->email, $this->keys['public']);

    $cacheKey = (string) config('pgp-mailer.cache.prefix', 'pgp-mailer:key:').$this->email;
    expect(Cache::get($cacheKey))->toBeNull();
    expect($resolver->forEmail($this->email))->not->toBeNull();
});

it('transferEmail() moves a row from one address to another', function (): void {
    config()->set('pgp-mailer.require_uid_match', false);
    PgpKey::store('old@example.com', $this->keys['public']);

    Event::fake([PgpKeyUidMismatch::class]);
    $row = PgpKey::transferEmail('old@example.com', 'new@example.com');

    expect($row)->not->toBeNull();
    expect($row->email)->toBe('new@example.com');
    expect($row->uid_mismatch_at)->toBeNull();
    Event::assertNotDispatched(PgpKeyUidMismatch::class);
});

it('transferEmail() with flagMismatch flags the row and dispatches PgpKeyUidMismatch', function (): void {
    config()->set('pgp-mailer.require_uid_match', false);
    PgpKey::store('old@example.com', $this->keys['public']);

    Event::fake([PgpKeyUidMismatch::class]);
    $row = PgpKey::transferEmail('old@example.com', 'new@example.com', flagMismatch: true);

    expect($row)->not->toBeNull();
    expect($row->email)->toBe('new@example.com');
    expect($row->uid_mismatch_at)->not->toBeNull();
    Event::assertDispatched(PgpKeyUidMismatch::class);
});

it('transferEmail() returns null when source has no row', function (): void {
    expect(PgpKey::transferEmail('nobody@example.com', 'someone@example.com'))->toBeNull();
});

it('transferEmail() returns null when source equals destination', function (): void {
    config()->set('pgp-mailer.require_uid_match', false);
    PgpKey::store('alice@example.com', $this->keys['public']);

    expect(PgpKey::transferEmail('alice@example.com', 'alice@example.com'))->toBeNull();
});

it('transferEmail() forgets cache for both old and new emails', function (): void {
    config()->set('pgp-mailer.require_uid_match', false);
    PgpKey::store('old@example.com', $this->keys['public']);

    $resolver = app(KeyResolver::class);
    $resolver->forEmail('old@example.com'); // warm cache

    $prefix = (string) config('pgp-mailer.cache.prefix');
    expect(Cache::get($prefix.'old@example.com'))->not->toBeNull();

    PgpKey::transferEmail('old@example.com', 'new@example.com');

    expect(Cache::get($prefix.'old@example.com'))->toBeNull();
    expect(Cache::get($prefix.'new@example.com'))->toBeNull();
});

it('purgeEmail() deletes the row and dispatches PgpKeyRemoved', function (): void {
    PgpKey::store($this->email, $this->keys['public']);

    Event::fake([PgpKeyRemoved::class]);
    $purged = PgpKey::purgeEmail($this->email);

    expect($purged)->toBeTrue();
    expect(PgpKey::query()->count())->toBe(0);
    Event::assertDispatched(PgpKeyRemoved::class);
});

it('purgeEmail() returns false when no row exists', function (): void {
    Event::fake([PgpKeyRemoved::class]);

    expect(PgpKey::purgeEmail('nobody@example.com'))->toBeFalse();
    Event::assertNotDispatched(PgpKeyRemoved::class);
});

it('EloquentKeyResolver uses the configured model class', function (): void {
    $subclass = new class extends PgpKey
    {
        public static int $queries = 0;

        public function newQuery()
        {
            self::$queries++;

            return parent::newQuery();
        }
    };

    config()->set('pgp-mailer.model', $subclass::class);
    config()->set('pgp-mailer.cache.enabled', false);
    PgpKey::store($this->email, $this->keys['public']);

    $subclass::$queries = 0;
    $resolver = app(KeyResolver::class);
    $key = $resolver->forEmail($this->email);

    expect($key)->not->toBeNull();
    expect($subclass::$queries)->toBeGreaterThan(0);
});
