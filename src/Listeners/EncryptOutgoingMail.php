<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Listeners;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Mail\Events\MessageSending;
use Illuminate\Mail\Mailer;
use Psr\Log\LoggerInterface;
use Symfony\Component\Mailer\Envelope;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\Part\AbstractPart;
use Throwable;
use Vpsbg\PgpMailer\Contracts\KeyResolver;
use Vpsbg\PgpMailer\Contracts\MissingKeyPolicy;
use Vpsbg\PgpMailer\Contracts\SigningKeyResolver;
use Vpsbg\PgpMailer\Engines\GnupgExtensionEngine;
use Vpsbg\PgpMailer\Events\PgpEncryptionApplied;
use Vpsbg\PgpMailer\Events\PgpEncryptionFailed;
use Vpsbg\PgpMailer\Events\PgpSigningApplied;
use Vpsbg\PgpMailer\Exceptions\MissingRecipientKeyException;
use Vpsbg\PgpMailer\Exceptions\MissingSenderKeyException;
use Vpsbg\PgpMailer\Mime\PgpMimeBuilder;
use Vpsbg\PgpMailer\Support\ArmoredKey;
use Vpsbg\PgpMailer\Support\Headers;
use Vpsbg\PgpMailer\Support\SigningKey;

class EncryptOutgoingMail
{
    public function __construct(
        protected GnupgExtensionEngine $engine,
        protected KeyResolver $resolver,
        protected SigningKeyResolver $signingKeyResolver,
        protected ConfigRepository $config,
        protected Application $app,
        protected Dispatcher $events,
        protected LoggerInterface $logger,
    ) {}

    public function handle(MessageSending $event): ?bool
    {
        $email = $event->message;
        $headers = $email->getHeaders();

        if ($headers->has(Headers::APPLIED)) {
            return null;
        }

        if ($headers->has(Headers::OPT_OUT)) {
            $headers->remove(Headers::OPT_OUT);

            return null;
        }

        // Signing is mandatory: without a signing key the package can only
        // produce plaintext on the wire, which violates the sign-only /
        // sign+encrypt invariant. Become a no-op so mail flows untouched.
        if (! $this->signingEnabled()) {
            $headers->remove(Headers::NO_ENCRYPT);

            return null;
        }

        $userNoEncrypt = $headers->has(Headers::NO_ENCRYPT);
        $headers->remove(Headers::NO_ENCRYPT);

        $recipients = $this->collectRecipients($email);
        if ($recipients === []) {
            $headers->remove(Headers::VISIBLE_SUBJECT);

            return null;
        }

        $protectedSubject = $this->extractProtectedSubject($email);

        if ($userNoEncrypt) {
            return $this->executeSignOnly($email, $recipients, $this->loadSigningCredentials($email), $protectedSubject);
        }

        try {
            $keys = $this->resolver->forEmails($recipients);
        } catch (Throwable $e) {
            $this->log('error', 'key resolution failed; falling back to sign-only', ['exception' => $e::class]);

            return $this->executeSignOnly($email, $recipients, $this->loadSigningCredentials($email), $protectedSubject);
        }

        $missing = array_values(array_diff($recipients, array_keys($keys)));
        $policy = MissingKeyPolicy::fromConfig((string) $this->config->get('pgp-mailer.missing_key_policy'));

        if ($missing !== []) {
            $resolution = $this->applyMissingKeyPolicy($policy, $missing);
            if ($resolution === 'halt') {
                return false;
            }
            if ($resolution === 'sign_only') {
                return $this->executeSignOnly($email, $recipients, $this->loadSigningCredentials($email), $protectedSubject);
            }
            // 'continue' — encrypt with the keys we have; split flow handles the rest.
        }

        // Encryption requires signing. Resolve the signing key once and
        // reuse it: if the sender has no key (UseDefault-with-no-default
        // or Skip policy), fall through to sign-only — which is itself a
        // no-op when no key resolves. The Fail policy throws and bubbles.
        $signingKey = $this->loadSigningCredentials($email);

        if ($keys === [] || $signingKey === null) {
            return $this->executeSignOnly($email, $recipients, $signingKey, $protectedSubject);
        }

        return $this->executeEncrypt($email, $keys, $missing, $policy, $signingKey, $protectedSubject);
    }

    /** @param  list<string>  $recipients */
    private function executeSignOnly(Email $email, array $recipients, ?SigningKey $signingKey, ?string $protectedSubject): ?bool
    {
        if ($signingKey === null) {
            // signingEnabled() said yes but no key actually resolved for
            // this sender (no per-sender entry + no default, unreadable
            // path, or Skip policy). Let the message go untouched.
            return null;
        }

        $body = $email->getBody();

        if ($protectedSubject !== null) {
            $this->applyProtectedHeadersToBody($body, $protectedSubject);
        }

        try {
            $signature = $this->engine->sign($body->toString(), $signingKey->armored, $signingKey->passphrase);
        } catch (Throwable $e) {
            return $this->handleEngineFailure($e, recipients: $recipients);
        }

        $email->setBody(PgpMimeBuilder::wrapSigned($body, $signature));
        $email->getHeaders()->addTextHeader(Headers::APPLIED, '1');

        if ($protectedSubject !== null) {
            $this->rewriteOuterSubject($email);
        }

        $this->events->dispatch(new PgpSigningApplied(recipients: $recipients));

        return null;
    }

    /**
     * @param  array<string, ArmoredKey>  $keys
     * @param  list<string>  $missing
     */
    private function executeEncrypt(
        Email $email,
        array $keys,
        array $missing,
        MissingKeyPolicy $policy,
        SigningKey $signingKey,
        ?string $protectedSubject,
    ): ?bool {
        if ($protectedSubject !== null) {
            $this->applyProtectedHeadersToBody($email->getBody(), $protectedSubject);
        }

        try {
            $ciphertext = $this->engine->encrypt(
                $email->getBody()->toString(),
                array_values($keys),
                $signingKey->armored,
                $signingKey->passphrase,
            );
        } catch (Throwable $e) {
            $this->events->dispatch(new PgpEncryptionFailed(array_keys($keys), $e));

            return $this->handleEngineFailure($e);
        }

        if ($missing !== [] && $policy === MissingKeyPolicy::SignOnly && $this->splitRecipientsEnabled()) {
            $missingAddresses = $this->extractAddresses($email, $missing);
            $this->restrictRecipientsTo($email, array_keys($keys));
            $this->dispatchSecondaryCopy($email, $missingAddresses, $signingKey, $protectedSubject);
        }

        $email->setBody(PgpMimeBuilder::wrap($ciphertext));
        $email->getHeaders()->addTextHeader(Headers::APPLIED, '1');

        if ($protectedSubject !== null) {
            $this->rewriteOuterSubject($email);
        }

        $this->events->dispatch(new PgpEncryptionApplied(
            recipients: array_keys($keys),
            fingerprints: array_values(array_map(
                fn (ArmoredKey $k): string => $k->fingerprint->longKeyId(),
                $keys,
            )),
            signed: true,
        ));

        return null;
    }

    /** @param  list<string>  $recipients */
    private function handleEngineFailure(Throwable $e, array $recipients = []): bool
    {
        // A misconfigured per-sender signing map (unmatched_sender_policy=fail)
        // is an operator error, not a transient engine failure. Bubble it up
        // so the caller sees it rather than silently dropping the send.
        if ($e instanceof MissingSenderKeyException) {
            throw $e;
        }

        $policy = (string) $this->config->get('pgp-mailer.engine_failure_policy', 'drop');

        $this->log('error', 'pgp operation failed; applying engine_failure_policy', [
            'policy' => $policy,
            'exception' => $e::class,
            'recipients' => $recipients,
        ]);

        if ($policy === 'fail') {
            throw $e;
        }

        return false;
    }

    /**
     * Returns 'halt' (drop the send), 'sign_only' (whole audience falls
     * back to multipart/signed), or 'continue' (proceed with the keys we
     * have; the caller decides whether to split the unkeyed copy).
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

            case MissingKeyPolicy::SignOnly:
                return $this->splitRecipientsEnabled() ? 'continue' : 'sign_only';
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

    /**
     * Build and dispatch the multipart/signed copy to recipients without
     * keys. Sent via the Symfony transport directly (not through
     * Mailer::send) so the MessageSending event does NOT re-fire — we've
     * already decided what this copy should be.
     *
     * @param  array{to: list<Address>, cc: list<Address>, bcc: list<Address>}  $missingAddresses
     */
    private function dispatchSecondaryCopy(Email $email, array $missingAddresses, SigningKey $signingKey, ?string $protectedSubject): void
    {
        if ($missingAddresses['to'] === [] && $missingAddresses['cc'] === [] && $missingAddresses['bcc'] === []) {
            return;
        }

        $copy = clone $email;
        $copy->to(...$missingAddresses['to']);
        $copy->cc(...$missingAddresses['cc']);
        $copy->bcc(...$missingAddresses['bcc']);

        try {
            $body = $copy->getBody();
            // The clone already inherited the inner Subject header that
            // executeEncrypt() added to $email->getBody() before us, so the
            // signed payload is identically protected. We only need to
            // rewrite the outer Subject on the copy here.
            $signature = $this->engine->sign($body->toString(), $signingKey->armored, $signingKey->passphrase);
            $copy->setBody(PgpMimeBuilder::wrapSigned($body, $signature));
            $copy->getHeaders()->addTextHeader(Headers::APPLIED, '1');
            if ($protectedSubject !== null) {
                $this->rewriteOuterSubject($copy);
            }
            $this->events->dispatch(new PgpSigningApplied(recipients: $this->collectRecipients($copy)));
        } catch (Throwable $e) {
            $this->log('error', 'signing the secondary copy failed; dropping it', [
                'exception' => $e::class,
                'message' => $e->getMessage(),
            ]);

            return;
        }

        try {
            $mailer = $this->app->make(Mailer::class);
            $transport = $mailer->getSymfonyTransport();
            $transport->send($copy, Envelope::create($copy));
        } catch (Throwable $e) {
            $this->log('error', 'secondary-copy dispatch failed', ['exception' => $e::class]);
        }
    }

    /**
     * Cheap master-switch check: signing is configured if it's enabled AND
     * at least one of (default key, default key_path, per-sender entries)
     * is present. The actual per-message key lookup happens in
     * loadSigningCredentials() via the SigningKeyResolver.
     */
    private function signingEnabled(): bool
    {
        if (! (bool) $this->config->get('pgp-mailer.signing.enabled', false)) {
            return false;
        }

        if ($this->config->get('pgp-mailer.signing.key_path')
            || $this->config->get('pgp-mailer.signing.key')) {
            return true;
        }

        $senders = $this->config->get('pgp-mailer.signing.senders');

        return is_array($senders) && $senders !== [];
    }

    /**
     * Resolve the signing key to use for this specific message. Looks at
     * the Email's From header and asks the SigningKeyResolver. Returns null
     * when no key is configured for this sender and the resolver's policy
     * is UseDefault-with-no-default or Skip; throws MissingSenderKeyException
     * when the policy is Fail.
     */
    private function loadSigningCredentials(Email $email): ?SigningKey
    {
        $from = $email->getFrom();
        $fromAddress = $from !== [] ? strtolower($from[0]->getAddress()) : null;

        return $this->signingKeyResolver->forSender($fromAddress);
    }

    private function splitRecipientsEnabled(): bool
    {
        return (bool) $this->config->get('pgp-mailer.sign_only.split_recipients', true);
    }

    /**
     * Decide whether protected headers apply to this message and return the
     * Subject that should be embedded inside the signed/encrypted body. The
     * per-message opt-out header is stripped here so it never reaches the
     * wire even when protection is disabled globally. Returns null when
     * either the feature is off, the caller opted out, or the Email has no
     * Subject worth protecting.
     */
    private function extractProtectedSubject(Email $email): ?string
    {
        $headers = $email->getHeaders();
        $optOut = $headers->has(Headers::VISIBLE_SUBJECT);
        $headers->remove(Headers::VISIBLE_SUBJECT);

        if ($optOut) {
            return null;
        }

        if (! (bool) $this->config->get('pgp-mailer.protected_headers.enabled', false)) {
            return null;
        }

        $subject = $email->getSubject();

        return ($subject !== null && $subject !== '') ? $subject : null;
    }

    /**
     * Rewrite the outer Subject with the configured placeholder. Called
     * after the engine has successfully produced its sign/encrypt payload —
     * if anything earlier in the path throws, the original Subject stays
     * visible (the inner-body Subject header we already added is harmless
     * to a discarded Email object).
     */
    private function rewriteOuterSubject(Email $email): void
    {
        $placeholder = (string) $this->config->get('pgp-mailer.protected_headers.placeholder_subject', '...');
        $email->subject($placeholder);
    }

    /**
     * Attach the protected Subject to the inner body part and mark its
     * Content-Type with `protected-headers="v1"`. The marker is the
     * recognition cue from draft-ietf-lamps-header-protection that
     * modern MUAs (Thunderbird's RNP-based OpenPGP, recent Apple Mail)
     * require before they swap the displayed Subject for the inner one.
     * Legacy memory-hole MUAs (ProtonMail, K-9) swap on the inner Subject
     * header alone and ignore the extra Content-Type parameter, so this
     * is additive — no MUA that worked before regresses.
     *
     * Implementation note: we pre-set Content-Type as a ParameterizedHeader
     * on the part's raw header collection. When the part's
     * getPreparedHeaders() later calls setHeaderBody('Content-Type', ...),
     * Symfony updates only the header value (e.g. "text/html"); parameters
     * stored on ParameterizedHeader survive the update. See
     * Symfony\Component\Mime\Header\ParameterizedHeader::$parameters.
     */
    private function applyProtectedHeadersToBody(AbstractPart $body, string $subject): void
    {
        $body->getHeaders()->addTextHeader('Subject', $subject);
        $body->getHeaders()->addParameterizedHeader(
            'Content-Type',
            $body->getMediaType().'/'.$body->getMediaSubtype(),
            ['protected-headers' => 'v1'],
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
