<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Resolvers;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Psr\Log\LoggerInterface;
use Vpsbg\PgpMailer\Contracts\SigningKeyResolver;
use Vpsbg\PgpMailer\Contracts\UnmatchedSenderPolicy;
use Vpsbg\PgpMailer\Exceptions\MissingSenderKeyException;
use Vpsbg\PgpMailer\Support\SigningKey;

/**
 * Default {@see SigningKeyResolver} backed by `config/pgp-mailer.php`.
 *
 * Resolution order for a given From address:
 *   1. Exact (case-insensitive) match in `signing.senders`.
 *   2. Otherwise, apply `signing.unmatched_sender_policy`:
 *      - use_default → top-level `signing.key` / `signing.key_path`
 *      - skip        → return null
 *      - fail        → throw MissingSenderKeyException
 *
 * Filesystem reads (`key_path`) are lazy: the file is read only when the
 * resolver actually selects that entry.
 */
class ConfigSigningKeyResolver implements SigningKeyResolver
{
    public function __construct(
        protected ConfigRepository $config,
        protected Application $app,
        protected LoggerInterface $logger,
    ) {}

    public function forSender(?string $fromAddress): ?SigningKey
    {
        if ($fromAddress !== null) {
            $match = $this->findSenderEntry($fromAddress);
            if ($match !== null) {
                [$label, $entry] = $match;
                $key = $this->materialize($entry, $label);
                if ($key !== null) {
                    return $key;
                }
                // Entry exists but the configured path was unreadable
                // or the inline key empty. Fall through to the policy.
            }
        }

        return match ($this->unmatchedPolicy()) {
            UnmatchedSenderPolicy::UseDefault => $this->loadDefault(),
            UnmatchedSenderPolicy::Skip => null,
            UnmatchedSenderPolicy::Fail => throw (new MissingSenderKeyException(
                'PGP signing: no signing key configured for sender '
                .($fromAddress ?? '(no From header)')
                .'; refusing to send under unmatched_sender_policy=fail.'
            ))->withSender($fromAddress),
        };
    }

    /**
     * Locate the per-sender entry whose key matches $fromAddress case-insensitively.
     *
     * @return array{0: string, 1: array<string, mixed>}|null
     */
    private function findSenderEntry(string $fromAddress): ?array
    {
        $senders = $this->config->get('pgp-mailer.signing.senders', []);
        if (! is_array($senders)) {
            return null;
        }

        $needle = strtolower($fromAddress);
        foreach ($senders as $email => $entry) {
            if (is_string($email) && is_array($entry) && strtolower($email) === $needle) {
                return [$email, $entry];
            }
        }

        return null;
    }

    private function loadDefault(): ?SigningKey
    {
        return $this->materialize([
            'key_path' => $this->config->get('pgp-mailer.signing.key_path'),
            'key' => $this->config->get('pgp-mailer.signing.key'),
            'passphrase' => $this->config->get('pgp-mailer.signing.passphrase'),
        ], 'default');
    }

    /**
     * Build a SigningKey from a config entry. `key_path` wins over inline `key`
     * when both are set; an unreadable path is logged and treated as "no key
     * for this entry" (caller falls through to the policy).
     *
     * @param  array<string, mixed>  $entry
     */
    private function materialize(array $entry, string $label): ?SigningKey
    {
        $path = $entry['key_path'] ?? null;
        $inline = $entry['key'] ?? null;
        $passphrase = $entry['passphrase'] ?? null;
        $passphrase = is_string($passphrase) ? $passphrase : null;

        if (is_string($path) && $path !== '') {
            if (! is_readable($path)) {
                $this->log('error', 'signing key path is not readable; signing disabled for sender', [
                    'sender' => $label,
                    'path' => $path,
                ]);

                return null;
            }

            $armored = @file_get_contents($path);
            if (! is_string($armored) || $armored === '') {
                return null;
            }

            return new SigningKey($armored, $passphrase);
        }

        if (is_string($inline) && $inline !== '') {
            return new SigningKey($inline, $passphrase);
        }

        return null;
    }

    private function unmatchedPolicy(): UnmatchedSenderPolicy
    {
        return UnmatchedSenderPolicy::fromConfig(
            (string) $this->config->get('pgp-mailer.signing.unmatched_sender_policy', 'use_default')
        );
    }

    /** @param  array<string, mixed>  $context */
    private function log(string $level, string $message, array $context = []): void
    {
        $channel = $this->config->get('pgp-mailer.log_channel');
        $logger = is_string($channel) && $channel !== ''
            ? $this->app->make('log')->channel($channel)
            : $this->logger;

        $logger->{$level}('pgp-mailer: '.$message, $context);
    }
}
