<?php

declare(strict_types=1);

use Vpsbg\PgpMailer\Contracts\KeyResolver;
use Vpsbg\PgpMailer\Resolvers\ChainKeyResolver;
use Vpsbg\PgpMailer\Support\ArmoredKey;
use Vpsbg\PgpMailer\Support\Fingerprint;

beforeEach(function (): void {
    $this->makeKey = fn (?string $fp = null): ArmoredKey => new ArmoredKey(
        armored: '-----BEGIN PGP PUBLIC KEY BLOCK-----STUB-----END PGP PUBLIC KEY BLOCK-----',
        fingerprint: Fingerprint::fromHex($fp ?? str_repeat('A', 40)),
        uids: ['Alice <alice@example.com>'],
    );

    $this->recording = fn (array $known): KeyResolver => new class($known) implements KeyResolver
    {
        /** @var list<array{0: string, 1: mixed}> */
        public array $calls = [];

        public function __construct(private array $known) {}

        public function forEmail(string $email): ?ArmoredKey
        {
            $this->calls[] = ['forEmail', $email];

            return $this->known[strtolower(trim($email))] ?? null;
        }

        public function forEmails(iterable $emails): array
        {
            $list = [];
            foreach ($emails as $email) {
                $list[] = strtolower(trim($email));
            }
            $this->calls[] = ['forEmails', $list];

            $result = [];
            foreach ($list as $email) {
                if (isset($this->known[$email])) {
                    $result[$email] = $this->known[$email];
                }
            }

            return $result;
        }
    };
});

it('forEmail returns the first non-null and short-circuits', function (): void {
    $key = ($this->makeKey)();
    $first = ($this->recording)(['alice@example.com' => $key]);
    $second = ($this->recording)([]);
    $chain = new ChainKeyResolver([$first, $second]);

    $result = $chain->forEmail('alice@example.com');

    expect($result)->toBe($key);
    expect($first->calls)->toBe([['forEmail', 'alice@example.com']]);
    expect($second->calls)->toBe([]);
});

it('forEmail falls through when the first resolver misses', function (): void {
    $key = ($this->makeKey)(str_repeat('B', 40));
    $first = ($this->recording)([]);
    $second = ($this->recording)(['alice@example.com' => $key]);
    $chain = new ChainKeyResolver([$first, $second]);

    $result = $chain->forEmail('alice@example.com');

    expect($result)->toBe($key);
    expect($first->calls)->toBe([['forEmail', 'alice@example.com']]);
    expect($second->calls)->toBe([['forEmail', 'alice@example.com']]);
});

it('forEmails passes only unresolved emails downstream', function (): void {
    $aKey = ($this->makeKey)(str_repeat('A', 40));
    $bKey = ($this->makeKey)(str_repeat('B', 40));
    $first = ($this->recording)(['a@example.com' => $aKey]);
    $second = ($this->recording)(['b@example.com' => $bKey]);
    $chain = new ChainKeyResolver([$first, $second]);

    $result = $chain->forEmails(['a@example.com', 'b@example.com', 'c@example.com']);

    expect(array_keys($result))->toEqualCanonicalizing(['a@example.com', 'b@example.com']);
    expect($result['a@example.com'])->toBe($aKey);
    expect($result['b@example.com'])->toBe($bKey);

    expect($first->calls[0][0])->toBe('forEmails');
    expect($first->calls[0][1])->toEqualCanonicalizing(['a@example.com', 'b@example.com', 'c@example.com']);
    expect($second->calls[0][0])->toBe('forEmails');
    expect($second->calls[0][1])->toEqualCanonicalizing(['b@example.com', 'c@example.com']);
});

it('forEmails stops calling downstream resolvers once all emails are resolved', function (): void {
    $aKey = ($this->makeKey)();
    $first = ($this->recording)(['a@example.com' => $aKey]);
    $second = ($this->recording)([]);
    $chain = new ChainKeyResolver([$first, $second]);

    $result = $chain->forEmails(['a@example.com']);

    expect($result)->toHaveKey('a@example.com');
    expect($second->calls)->toBe([]);
});

it('forEmails normalizes emails before delegation', function (): void {
    $aKey = ($this->makeKey)();
    $first = ($this->recording)(['alice@example.com' => $aKey]);
    $chain = new ChainKeyResolver([$first]);

    $result = $chain->forEmails(['  Alice@Example.COM  ']);

    expect($result)->toHaveKey('alice@example.com');
});
