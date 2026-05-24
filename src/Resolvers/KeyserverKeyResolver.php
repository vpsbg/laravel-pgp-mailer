<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Resolvers;

use Illuminate\Contracts\Cache\LockProvider;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Support\Facades\Cache;
use Throwable;
use Vpsbg\PgpMailer\Contracts\KeyResolver;
use Vpsbg\PgpMailer\Engines\GnupgExtensionEngine;
use Vpsbg\PgpMailer\Events\PgpKeyserverFetchFailed;
use Vpsbg\PgpMailer\Events\PgpKeyserverFetchSucceeded;
use Vpsbg\PgpMailer\Exceptions\KeyParsingException;
use Vpsbg\PgpMailer\Models\PgpKey;
use Vpsbg\PgpMailer\Support\ArmoredKey;

/**
 * Fetches recipient public keys from a single configurable keyserver
 * (HKP or VKS) when the inner resolver returns nothing. On success the
 * key is optionally persisted via PgpKey::store() so the next send hits
 * the local DB. The resolver never throws to its caller — every failure
 * mode resolves to null + a PgpKeyserverFetchFailed event.
 */
class KeyserverKeyResolver implements KeyResolver
{
    public function __construct(
        protected GnupgExtensionEngine $engine,
        protected ConfigRepository $config,
        protected HttpFactory $http,
        protected Dispatcher $events,
    ) {}

    public function forEmail(string $email): ?ArmoredKey
    {
        $normalized = strtolower(trim($email));
        if ($normalized === '') {
            return null;
        }

        if ($this->isNegativelyCached($normalized)) {
            return null;
        }

        return $this->withFetchLock($normalized, function () use ($normalized): ?ArmoredKey {
            // Re-check negative cache inside the lock — a sibling worker
            // may have just recorded a miss for this email.
            if ($this->isNegativelyCached($normalized)) {
                return null;
            }

            return $this->doFetch($normalized);
        });
    }

    public function forEmails(iterable $emails): array
    {
        $seen = [];
        $result = [];

        foreach ($emails as $email) {
            $normalized = strtolower(trim($email));
            if ($normalized === '' || isset($seen[$normalized])) {
                continue;
            }
            $seen[$normalized] = true;

            $key = $this->forEmail($normalized);
            if ($key !== null) {
                $result[$normalized] = $key;
            }
        }

        return $result;
    }

    protected function doFetch(string $email): ?ArmoredKey
    {
        $url = $this->buildUrl($email);
        $timeout = max(1, (int) $this->config->get('pgp-mailer.keyserver.timeout', 3));
        $verifyTls = (bool) $this->config->get('pgp-mailer.keyserver.verify_tls', true);
        $userAgent = (string) $this->config->get('pgp-mailer.keyserver.user_agent', 'laravel-pgp-mailer');

        try {
            $response = $this->http
                ->withOptions(['verify' => $verifyTls])
                ->timeout($timeout)
                ->withUserAgent($userAgent)
                ->get($url);
        } catch (ConnectionException $e) {
            $reason = $this->classifyConnectionException($e);
            $this->recordMiss($email, $reason, null);

            return null;
        } catch (Throwable) {
            $this->recordMiss($email, 'transport', null);

            return null;
        }

        $status = $response->status();

        if ($status === 404) {
            $this->recordMiss($email, 'not_found', 404);

            return null;
        }

        if (! $response->successful()) {
            $this->recordMiss($email, 'transport', $status);

            return null;
        }

        $body = trim($response->body());
        if ($body === '') {
            $this->recordMiss($email, 'parse_failed', $status);

            return null;
        }

        try {
            $parsed = $this->engine->parsePublicKey($body);
        } catch (Throwable) {
            $this->recordMiss($email, 'parse_failed', $status);

            return null;
        }

        if ($parsed->isExpired()) {
            $this->recordMiss($email, 'expired', $status);

            return null;
        }

        if ($parsed->revoked) {
            $this->recordMiss($email, 'revoked', $status);

            return null;
        }

        // Enforce the "never encrypt to a key whose UID lies" invariant on
        // every fetched key, independent of `keyserver.persist`. The persist
        // branch below also catches a KeyParsingException from PgpKey::store
        // as defense-in-depth, but the authoritative check lives here so the
        // persist=false path is held to the same standard.
        $requireUidMatch = (bool) $this->config->get('pgp-mailer.require_uid_match', true);
        if ($requireUidMatch && ! $parsed->hasUidMatching($email)) {
            $this->recordMiss($email, 'uid_mismatch', $status);

            return null;
        }

        $persist = (bool) $this->config->get('pgp-mailer.keyserver.persist', true);
        $persisted = false;

        if ($persist) {
            try {
                $this->persist($email, $body);
                $persisted = true;
            } catch (KeyParsingException) {
                // UID-mismatch or other validation failure from PgpKey::store().
                // Treat as a miss — never encrypt to a key whose UID lies.
                $this->recordMiss($email, 'uid_mismatch', $status);

                return null;
            } catch (Throwable) {
                // Persistence failure (DB connection, unique race, etc.).
                // The fetched key is still valid for this send; fall through
                // and return it. Don't log noisily — the next send will
                // either find the row already there (unique constraint) or
                // re-fetch and try again.
                $persisted = false;
            }
        }

        $this->events->dispatch(new PgpKeyserverFetchSucceeded(
            email: $email,
            fingerprint: $parsed->fingerprint,
            persisted: $persisted,
        ));

        return $parsed;
    }

    protected function persist(string $email, string $armored): void
    {
        $modelClass = (string) $this->config->get('pgp-mailer.model', PgpKey::class);
        /** @var class-string<PgpKey> $modelClass */
        $modelClass::store($email, $armored);
    }

    protected function buildUrl(string $email): string
    {
        $template = (string) $this->config->get(
            'pgp-mailer.keyserver.url_template',
            'https://keys.openpgp.org/vks/v1/by-email/{email}'
        );

        return str_replace('{email}', rawurlencode($email), $template);
    }

    protected function classifyConnectionException(ConnectionException $e): string
    {
        $message = strtolower($e->getMessage());

        if (str_contains($message, 'timed out')
            || str_contains($message, 'timeout')
            || str_contains($message, 'operation timed')) {
            return 'timeout';
        }

        return 'transport';
    }

    protected function recordMiss(string $email, string $reason, ?int $httpStatus): void
    {
        $ttl = (int) $this->config->get('pgp-mailer.keyserver.negative_cache_ttl', 3600);
        if ($ttl > 0) {
            $this->cache()->put($this->negativeCacheKey($email), $reason, $ttl);
        }

        $this->events->dispatch(new PgpKeyserverFetchFailed(
            email: $email,
            reason: $reason,
            httpStatus: $httpStatus,
        ));
    }

    protected function isNegativelyCached(string $email): bool
    {
        $ttl = (int) $this->config->get('pgp-mailer.keyserver.negative_cache_ttl', 3600);
        if ($ttl <= 0) {
            return false;
        }

        return $this->cache()->has($this->negativeCacheKey($email));
    }

    protected function negativeCacheKey(string $email): string
    {
        $prefix = (string) $this->config->get(
            'pgp-mailer.keyserver.cache_prefix',
            'pgp-mailer:ks-miss:'
        );

        return $prefix.$email;
    }

    /**
     * @template T
     *
     * @param  \Closure(): T  $callback
     * @return T
     */
    protected function withFetchLock(string $email, \Closure $callback): mixed
    {
        $prefix = (string) $this->config->get(
            'pgp-mailer.keyserver.lock_prefix',
            'pgp-mailer:ks-fetch:'
        );
        $cache = $this->cache();

        if (! $cache instanceof LockProvider) {
            // Cache store does not implement the atomic-lock contract. Fall
            // back to running without the coalescing guarantee; the DB
            // unique constraint on `email` is still the correctness backstop.
            return $callback();
        }

        try {
            $lock = $cache->lock($prefix.$email, 10);
            $lock->block(5);
        } catch (Throwable) {
            return $callback();
        }

        try {
            return $callback();
        } finally {
            try {
                $lock->release();
            } catch (Throwable) {
                // Best-effort release; ignore.
            }
        }
    }

    protected function cache(): CacheRepository
    {
        $store = $this->config->get('pgp-mailer.cache.store');

        return Cache::store($store);
    }
}
