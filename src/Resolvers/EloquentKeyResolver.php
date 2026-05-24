<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Resolvers;

use Closure;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Support\Facades\Cache;
use Vpsbg\PgpMailer\Contracts\KeyResolver;
use Vpsbg\PgpMailer\Engines\GnupgExtensionEngine;
use Vpsbg\PgpMailer\Exceptions\KeyParsingException;
use Vpsbg\PgpMailer\Models\PgpKey;
use Vpsbg\PgpMailer\Support\ArmoredKey;

class EloquentKeyResolver implements KeyResolver
{
    public function __construct(
        protected GnupgExtensionEngine $engine,
        protected ConfigRepository $config,
    ) {}

    public function forEmail(string $email): ?ArmoredKey
    {
        $normalized = strtolower(trim($email));

        return $this->fromCacheOr($normalized, function () use ($normalized): ?ArmoredKey {
            $row = $this->modelClass()::query()
                ->active()
                ->forEmail($normalized)
                ->first();

            return $row ? $this->parseRow($row) : null;
        });
    }

    public function forEmails(iterable $emails): array
    {
        $normalized = [];
        foreach ($emails as $email) {
            $normalized[] = strtolower(trim($email));
        }
        $normalized = array_values(array_unique(array_filter($normalized)));

        if ($normalized === []) {
            return [];
        }

        $result = [];
        $uncached = [];

        if ($this->cacheEnabled()) {
            foreach ($normalized as $email) {
                $cached = $this->cache()->get($this->cacheKey($email));
                if ($cached instanceof ArmoredKey) {
                    $result[$email] = $cached;
                } else {
                    $uncached[] = $email;
                }
            }
        } else {
            $uncached = $normalized;
        }

        if ($uncached !== []) {
            $rows = $this->modelClass()::query()
                ->active()
                ->whereIn('email', $uncached)
                ->get();

            foreach ($rows as $row) {
                $key = $this->parseRow($row);
                if ($key === null) {
                    continue;
                }
                $result[$row->email] = $key;

                if ($this->cacheEnabled()) {
                    $this->cache()->put($this->cacheKey($row->email), $key, $this->ttl());
                }
            }
        }

        return $result;
    }

    protected function parseRow(PgpKey $row): ?ArmoredKey
    {
        try {
            return $this->engine->parsePublicKey($row->public_key);
        } catch (KeyParsingException) {
            return null;
        }
    }

    /** @return class-string<PgpKey> */
    protected function modelClass(): string
    {
        /** @var class-string<PgpKey> $cls */
        $cls = (string) $this->config->get('pgp-mailer.model', PgpKey::class);

        return $cls;
    }

    protected function fromCacheOr(string $email, Closure $resolver): ?ArmoredKey
    {
        if (! $this->cacheEnabled()) {
            return $resolver();
        }

        $key = $this->cacheKey($email);
        $cached = $this->cache()->get($key);

        if ($cached instanceof ArmoredKey) {
            return $cached;
        }

        $value = $resolver();
        if ($value !== null) {
            $this->cache()->put($key, $value, $this->ttl());
        }

        return $value;
    }

    protected function cacheEnabled(): bool
    {
        return (bool) $this->config->get('pgp-mailer.cache.enabled', true);
    }

    protected function ttl(): int
    {
        return (int) $this->config->get('pgp-mailer.cache.ttl', 3600);
    }

    protected function cacheKey(string $email): string
    {
        return ((string) $this->config->get('pgp-mailer.cache.prefix', 'pgp-mailer:key:')).$email;
    }

    protected function cache(): CacheRepository
    {
        $store = $this->config->get('pgp-mailer.cache.store');

        return Cache::store($store);
    }
}
