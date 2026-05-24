<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Listeners;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Mail\Events\MessageSending;
use Illuminate\Mail\Mailer;
use Psr\Log\LoggerInterface;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;
use Throwable;
use Vpsbg\PgpMailer\Contracts\KeyResolver;
use Vpsbg\PgpMailer\Contracts\MissingKeyPolicy;
use Vpsbg\PgpMailer\Engines\GnupgExtensionEngine;
use Vpsbg\PgpMailer\Events\PgpEncryptionApplied;
use Vpsbg\PgpMailer\Events\PgpEncryptionFailed;
use Vpsbg\PgpMailer\Exceptions\MissingRecipientKeyException;
use Vpsbg\PgpMailer\Mime\PgpMimeBuilder;
use Vpsbg\PgpMailer\Support\ArmoredKey;
use Vpsbg\PgpMailer\Support\Headers;

class EncryptOutgoingMail
{
    public function __construct(
        protected GnupgExtensionEngine $engine,
        protected KeyResolver $resolver,
        protected ConfigRepository $config,
        protected Application $app,
        protected Dispatcher $events,
        protected LoggerInterface $logger,
    ) {}

    public function handle(MessageSending $event): ?bool
    {
        $email = $event->message;

        if ($email->getHeaders()->has(Headers::SKIP)) {
            $email->getHeaders()->remove(Headers::SKIP);

            return null;
        }

        if ($email->getHeaders()->has(Headers::APPLIED)) {
            return null;
        }

        if ($email->getHeaders()->has(Headers::OPT_OUT)) {
            $email->getHeaders()->remove(Headers::OPT_OUT);

            return null;
        }

        $recipients = $this->collectRecipients($email);
        if ($recipients === []) {
            return null;
        }

        try {
            $keys = $this->resolver->forEmails($recipients);
        } catch (Throwable $e) {
            $this->log('error', 'key resolution failed; sending plaintext', ['exception' => $e::class]);

            return null;
        }

        $missing = array_values(array_diff($recipients, array_keys($keys)));
        $policy = MissingKeyPolicy::fromConfig((string) $this->config->get('pgp-mailer.missing_key_policy'));

        if ($missing !== []) {
            $resolution = $this->applyMissingKeyPolicy($policy, $missing);
            if ($resolution === 'halt') {
                return false;
            }
            if ($resolution === 'plaintext') {
                return null;
            }
        }

        if ($keys === []) {
            return null;
        }

        try {
            $ciphertext = $this->encryptBody($email, $keys);
        } catch (Throwable $e) {
            $this->events->dispatch(new PgpEncryptionFailed(array_keys($keys), $e));

            $enginePolicy = MissingKeyPolicy::fromConfig(
                (string) $this->config->get('pgp-mailer.engine_failure_policy', 'drop')
            );

            $this->log('error', 'encryption failed; applying engine_failure_policy', [
                'policy' => $enginePolicy->value,
                'exception' => $e::class,
            ]);

            if ($enginePolicy === MissingKeyPolicy::Fail) {
                throw $e;
            }

            // Drop and Passthrough both short-circuit: we never silently send
            // plaintext because the engine misbehaved. Only LogOnly opts the
            // host explicitly into plaintext fallback.
            if ($enginePolicy === MissingKeyPolicy::LogOnly) {
                return null;
            }

            return false;
        }

        $signingActive = $this->signingEnabled();
        $missingAddresses = $this->extractAddresses($email, $missing);

        if ($missing !== [] && $policy === MissingKeyPolicy::Passthrough && $this->splitRecipientsEnabled()) {
            $this->restrictRecipientsTo($email, array_keys($keys));
            $this->dispatchPlaintextCopy($email, $missingAddresses);
        }

        $email->setBody(PgpMimeBuilder::wrap($ciphertext));
        $email->getHeaders()->addTextHeader(Headers::APPLIED, '1');

        $this->events->dispatch(new PgpEncryptionApplied(
            recipients: array_keys($keys),
            fingerprints: array_values(array_map(
                fn (ArmoredKey $k): string => $k->fingerprint->longKeyId(),
                $keys,
            )),
            signed: $signingActive,
        ));

        return null;
    }

    /** @param  array<string, ArmoredKey>  $keys */
    private function encryptBody(Email $email, array $keys): string
    {
        $inner = $email->getBody()->toString();

        [$signingArmored, $passphrase] = $this->loadSigningCredentials();

        return $this->engine->encrypt(
            $inner,
            array_values($keys),
            $signingArmored,
            $passphrase,
        );
    }

    /**
     * Returns 'halt' (drop the send), 'plaintext' (allow plaintext through),
     * or 'continue' (proceed with the keys we have).
     *
     * @param  list<string>  $missing
     */
    private function applyMissingKeyPolicy(MissingKeyPolicy $policy, array $missing): string
    {
        switch ($policy) {
            case MissingKeyPolicy::Fail:
                throw (new MissingRecipientKeyException(
                    'PGP missing-key policy = fail; refusing to send to recipients without keys: '
                    .implode(', ', $missing)
                ))->withMissingEmails($missing);

            case MissingKeyPolicy::Drop:
                $this->log('warning', 'dropping message; recipients have no PGP key', ['emails' => $missing]);

                return 'halt';

            case MissingKeyPolicy::LogOnly:
                $this->log('warning', 'sending plaintext; recipients have no PGP key', ['emails' => $missing]);

                return 'plaintext';

            case MissingKeyPolicy::Passthrough:
                if (! $this->splitRecipientsEnabled()) {
                    return 'plaintext';
                }

                return 'continue';
        }
    }

    /** @return list<string> */
    private function collectRecipients(Email $email): array
    {
        $out = [];
        foreach ([...$email->getTo(), ...$email->getCc(), ...$email->getBcc()] as $address) {
            $out[] = strtolower($address->getAddress());
        }

        return array_values(array_unique($out));
    }

    /**
     * @param  list<string>  $missing  Lowercased addresses to extract.
     * @return array{to: list<Address>, cc: list<Address>, bcc: list<Address>}
     */
    private function extractAddresses(Email $email, array $missing): array
    {
        $needle = array_flip($missing);
        $out = ['to' => [], 'cc' => [], 'bcc' => []];

        foreach (['to', 'cc', 'bcc'] as $field) {
            $getter = 'get'.ucfirst($field);
            foreach ($email->$getter() as $address) {
                if (isset($needle[strtolower($address->getAddress())])) {
                    $out[$field][] = $address;
                }
            }
        }

        return $out;
    }

    /** @param  list<string>  $keepLowercased */
    private function restrictRecipientsTo(Email $email, array $keepLowercased): void
    {
        $keep = array_flip($keepLowercased);

        foreach (['to', 'cc', 'bcc'] as $field) {
            $getter = 'get'.ucfirst($field);
            $kept = array_values(array_filter(
                $email->$getter(),
                fn (Address $a): bool => isset($keep[strtolower($a->getAddress())]),
            ));
            $email->$field(...$kept);
        }
    }

    /** @param  array{to: list<Address>, cc: list<Address>, bcc: list<Address>}  $missingAddresses */
    private function dispatchPlaintextCopy(Email $email, array $missingAddresses): void
    {
        if ($missingAddresses['to'] === [] && $missingAddresses['cc'] === [] && $missingAddresses['bcc'] === []) {
            return;
        }

        $copy = clone $email;
        $copy->to(...$missingAddresses['to']);
        $copy->cc(...$missingAddresses['cc']);
        $copy->bcc(...$missingAddresses['bcc']);
        $copy->getHeaders()->addTextHeader(Headers::SKIP, '1');

        try {
            $this->app->make(Mailer::class)->sendRawSymfonyMessage($copy);
        } catch (Throwable $e) {
            $this->log('error', 'plaintext fallback dispatch failed', ['exception' => $e::class]);
        }
    }

    private function signingEnabled(): bool
    {
        if (! (bool) $this->config->get('pgp-mailer.signing.enabled', false)) {
            return false;
        }

        return $this->config->get('pgp-mailer.signing.key_path') || $this->config->get('pgp-mailer.signing.key');
    }

    /** @return array{0: ?string, 1: ?string} [armoredPrivateKey, passphrase] */
    private function loadSigningCredentials(): array
    {
        if (! $this->signingEnabled()) {
            return [null, null];
        }

        $path = $this->config->get('pgp-mailer.signing.key_path');
        $inline = $this->config->get('pgp-mailer.signing.key');
        $passphrase = $this->config->get('pgp-mailer.signing.passphrase');

        if (is_string($path) && $path !== '') {
            if (! is_readable($path)) {
                $this->log('error', 'signing key path is not readable; signing disabled', ['path' => $path]);

                return [null, null];
            }
            $armored = file_get_contents($path) ?: null;
        } else {
            $armored = is_string($inline) ? $inline : null;
        }

        if ($armored === null || $armored === '') {
            return [null, null];
        }

        return [$armored, is_string($passphrase) ? $passphrase : null];
    }

    private function splitRecipientsEnabled(): bool
    {
        return (bool) $this->config->get('pgp-mailer.passthrough.split_recipients', true);
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
