<?php

declare(strict_types=1);

use Illuminate\Mail\Transport\ArrayTransport;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Mail;
use Symfony\Component\Mailer\SentMessage;
use Symfony\Component\Mime\Email;
use Vpsbg\PgpMailer\Engines\GnupgExtensionEngine;
use Vpsbg\PgpMailer\Events\PgpEncryptionApplied;
use Vpsbg\PgpMailer\Events\PgpEncryptionFailed;
use Vpsbg\PgpMailer\Exceptions\EncryptionFailedException;
use Vpsbg\PgpMailer\Exceptions\MissingRecipientKeyException;
use Vpsbg\PgpMailer\Models\PgpKey;
use Vpsbg\PgpMailer\PgpMailer;
use Vpsbg\PgpMailer\Tests\Stubs\PlainMailable;
use Vpsbg\PgpMailer\Tests\Stubs\PlaintextOnlyMailable;

beforeEach(function (): void {
    $this->keys = $this->fixtureKeys();
    $this->recipientEmail = $this->fixtureEmail();

    PgpKey::create([
        'email' => $this->recipientEmail,
        'public_key' => $this->keys['public'],
        'fingerprint' => '5C86E8EFCD946F05FDCC99A3F6AD4E436EB07FD0',
        'algorithm' => 'rsa2048',
    ]);
});

it('encrypts mail destined for a recipient that has a stored key', function (): void {
    Event::fake([PgpEncryptionApplied::class]);

    Mail::to($this->recipientEmail)->send(new PlainMailable('the encrypted payload'));

    $sent = sentMessages();
    expect($sent)->toHaveCount(1);

    $email = $sent[0]->getOriginalMessage();
    expect($email)->toBeInstanceOf(Email::class);

    $serialized = $email->toString();
    expect($serialized)->toContain('multipart/encrypted');
    expect($serialized)->toContain('protocol="application/pgp-encrypted"');
    expect($serialized)->toContain('-----BEGIN PGP MESSAGE-----');
    expect($serialized)->not->toContain('the encrypted payload');

    Event::assertDispatched(PgpEncryptionApplied::class);

    expect(recoverEncrypted($serialized, $this->keys['private']))->toContain('the encrypted payload');
});

it('does not encrypt when no recipient has a key (passthrough policy)', function (): void {
    PgpKey::query()->delete();
    config()->set('pgp-mailer.missing_key_policy', 'passthrough');

    Mail::to($this->recipientEmail)->send(new PlainMailable('plaintext please'));

    $sent = sentMessages();
    expect($sent)->toHaveCount(1);
    expect($sent[0]->getOriginalMessage()->toString())->toContain('plaintext please');
});

it('fail policy throws MissingRecipientKeyException and sends nothing', function (): void {
    PgpKey::query()->delete();
    config()->set('pgp-mailer.missing_key_policy', 'fail');

    try {
        Mail::to($this->recipientEmail)->send(new PlainMailable('would be plaintext'));
        expect()->fail('expected MissingRecipientKeyException');
    } catch (MissingRecipientKeyException $e) {
        expect($e->context()['missing_emails'] ?? '')->toContain($this->recipientEmail);
    }

    expect(sentMessages())->toHaveCount(0);
});

it('drop policy short-circuits without sending', function (): void {
    PgpKey::query()->delete();
    config()->set('pgp-mailer.missing_key_policy', 'drop');

    Mail::to($this->recipientEmail)->send(new PlainMailable('would be plaintext'));

    expect(sentMessages())->toHaveCount(0);
});

it('log_only policy sends plaintext', function (): void {
    PgpKey::query()->delete();
    config()->set('pgp-mailer.missing_key_policy', 'log_only');

    Mail::to($this->recipientEmail)->send(new PlainMailable('plaintext via log_only'));

    $sent = sentMessages();
    expect($sent)->toHaveCount(1);
    expect($sent[0]->getOriginalMessage()->toString())->toContain('plaintext via log_only');
});

it('encrypts to Bcc recipients too', function (): void {
    Mail::to('nobody-with-no-key@example.com')
        ->bcc($this->recipientEmail)
        ->send(new PlainMailable('bcc test payload'));

    // Mixed audience + default passthrough+split_recipients → encrypt for
    // the keyed Bcc, re-dispatch plaintext for the rest.
    $sent = sentMessages();
    expect(count($sent))->toBeGreaterThanOrEqual(1);

    $encrypted = null;
    foreach ($sent as $msg) {
        if (str_contains($msg->getOriginalMessage()->toString(), 'multipart/encrypted')) {
            $encrypted = $msg->getOriginalMessage();
            break;
        }
    }

    expect($encrypted)->not->toBeNull('expected at least one encrypted message');
    expect(recoverEncrypted($encrypted->toString(), $this->keys['private']))
        ->toContain('bcc test payload');
});

it('signs when signing is enabled in config', function (): void {
    config()->set('pgp-mailer.signing.enabled', true);
    config()->set('pgp-mailer.signing.key', $this->keys['private']);
    config()->set('pgp-mailer.signing.passphrase', null);

    Mail::to($this->recipientEmail)->send(new PlainMailable('signed payload'));

    $serialized = sentMessages()[0]->getOriginalMessage()->toString();
    expect($serialized)->toContain('-----BEGIN PGP MESSAGE-----');

    [$plaintext, $info] = gnupgDecryptVerify(
        extractArmoredCiphertext($serialized),
        $this->keys['private'],
    );

    expect($plaintext)->toContain('signed payload');
    expect($info)->not->toBeEmpty();
    expect($info[0]['fingerprint'] ?? '')->not->toBe('');
});

it('preserves attachments through the encryption round-trip', function (): void {
    $attachmentBody = "%PDF-1.4\nfake-pdf-bytes\n\xE2\x9C\xA8\n%%EOF";

    Mail::raw('mail body with attachment', function ($message) use ($attachmentBody): void {
        $message->to($this->recipientEmail);
        $message->subject('with attachment');
        $message->attachData($attachmentBody, 'test.pdf', ['mime' => 'application/pdf']);
    });

    $serialized = sentMessages()[0]->getOriginalMessage()->toString();
    expect($serialized)->toContain('-----BEGIN PGP MESSAGE-----');
    expect($serialized)->not->toContain('mail body with attachment');
    expect($serialized)->not->toContain('fake-pdf-bytes');

    $recovered = recoverEncrypted($serialized, $this->keys['private']);

    expect($recovered)->toContain('test.pdf');
    expect(str_contains($recovered, 'fake-pdf-bytes')
        || str_contains($recovered, base64_encode($attachmentBody))
    )->toBeTrue('attachment payload missing from decrypted inner MIME');
});

// Engine-failure policy: under default config, a throwing engine MUST NOT
// silently downgrade to plaintext.

it('default engine_failure_policy refuses to send plaintext on engine throw', function (): void {
    bindThrowingEngine();
    Event::fake([PgpEncryptionFailed::class]);

    config()->set('pgp-mailer.missing_key_policy', 'passthrough');

    Mail::to($this->recipientEmail)->send(new PlainMailable('SHOULD NOT LEAK'));

    expect(sentMessages())->toHaveCount(0);
    Event::assertDispatched(PgpEncryptionFailed::class);
});

it('engine_failure_policy=fail re-throws the engine exception', function (): void {
    bindThrowingEngine();
    config()->set('pgp-mailer.engine_failure_policy', 'fail');

    expect(fn () => Mail::to($this->recipientEmail)->send(new PlainMailable('boom')))
        ->toThrow(EncryptionFailedException::class);

    expect(sentMessages())->toHaveCount(0);
});

it('engine_failure_policy=log_only is the only path that allows plaintext fallback', function (): void {
    bindThrowingEngine();
    config()->set('pgp-mailer.engine_failure_policy', 'log_only');

    Mail::to($this->recipientEmail)->send(new PlainMailable('explicit plaintext'));

    $sent = sentMessages();
    expect($sent)->toHaveCount(1);
    expect($sent[0]->getOriginalMessage()->toString())->toContain('explicit plaintext');
});

// Mailable-native opt-out (recommended for Mailables you own).

it('honors a bypass header declared in Mailable::headers()', function (): void {
    Mail::to($this->recipientEmail)->send(new PlaintextOnlyMailable('newsletter body'));

    $sent = sentMessages();
    expect($sent)->toHaveCount(1);

    $serialized = $sent[0]->getOriginalMessage()->toString();
    expect($serialized)->not->toContain('-----BEGIN PGP MESSAGE-----');
    expect($serialized)->toContain('newsletter body');
    expect($serialized)->not->toContain('X-Pgp-Mailer-Disable');
});

// PgpMailer::skip() — wrap a Mailable you can't edit.

it('PgpMailer::skip wraps a Mailable to bypass encryption end-to-end', function (): void {
    $mailable = new PlainMailable('skip-helper payload');

    Mail::to($this->recipientEmail)->send(PgpMailer::skip($mailable));

    $sent = sentMessages();
    expect($sent)->toHaveCount(1);

    $serialized = $sent[0]->getOriginalMessage()->toString();
    expect($serialized)->not->toContain('-----BEGIN PGP MESSAGE-----');
    expect($serialized)->toContain('skip-helper payload');
    expect($serialized)->not->toContain('X-Pgp-Mailer-Disable');
});

it('PgpMailer::skip returns the same Mailable instance', function (): void {
    $mailable = new PlainMailable('whatever');

    expect(PgpMailer::skip($mailable))->toBe($mailable);
});

it('PgpMailer::skip is idempotent', function (): void {
    $mailable = new PlainMailable('double-skip payload');
    PgpMailer::skip($mailable);
    PgpMailer::skip($mailable);

    Mail::to($this->recipientEmail)->send($mailable);

    $serialized = sentMessages()[0]->getOriginalMessage()->toString();
    expect($serialized)->not->toContain('-----BEGIN PGP MESSAGE-----');
    expect($serialized)->toContain('double-skip payload');
});

it('skips encryption when the X-Pgp-Mailer-Disable header is set', function (): void {
    Mail::raw('opt-out payload', function ($message): void {
        $message->to($this->recipientEmail);
        $message->subject('opt-out');
        $message->getSymfonyMessage()->getHeaders()->addTextHeader('X-Pgp-Mailer-Disable', '1');
    });

    $serialized = sentMessages()[0]->getOriginalMessage()->toString();
    expect($serialized)->not->toContain('-----BEGIN PGP MESSAGE-----');
    expect($serialized)->toContain('opt-out payload');
    expect($serialized)->not->toContain('X-Pgp-Mailer-Disable');
});

function bindThrowingEngine(): void
{
    // Subclass the real engine so parsePublicKey still works (the resolver
    // needs to surface the recipient's key before the listener reaches the
    // encrypt step) but encrypt+sign blow up deterministically.
    $throwing = new class extends GnupgExtensionEngine
    {
        public function encrypt(string $payload, array $recipientKeys, ?string $signingPrivateKeyArmored = null, ?string $signingPassphrase = null): string
        {
            throw new EncryptionFailedException('synthetic engine failure');
        }

        public function sign(string $payload, string $signingPrivateKeyArmored, ?string $passphrase = null): string
        {
            throw new EncryptionFailedException('synthetic engine failure');
        }
    };

    app()->instance(GnupgExtensionEngine::class, $throwing);
}

// === Helpers ===========================================================

/** @return array<int, SentMessage> */
function sentMessages(): array
{
    /** @var ArrayTransport $transport */
    $transport = app('mailer')->getSymfonyTransport();

    return $transport->messages()->all();
}

function extractArmoredCiphertext(string $serializedMime): string
{
    if (! preg_match('/-----BEGIN PGP MESSAGE-----.*?-----END PGP MESSAGE-----/s', $serializedMime, $m)) {
        throw new RuntimeException('No PGP MESSAGE block found in serialized MIME');
    }

    // Strip quoted-printable soft-wrap markers, if any (we set 7bit but be defensive).
    return str_replace("=\r\n", '', $m[0]);
}

function recoverEncrypted(string $serializedMime, string $privateKeyArmored): string
{
    [$plaintext] = gnupgDecryptVerify(extractArmoredCiphertext($serializedMime), $privateKeyArmored);

    return $plaintext;
}

/**
 * Decrypt with the gnupg PECL extension in a throwaway homedir. Returns
 * [plaintext, signaturesInfo]. signaturesInfo is empty when the ciphertext
 * isn't signed; non-empty (one entry per signer) when it is.
 *
 * @return array{0: string, 1: array<int, array<string, mixed>>}
 */
function gnupgDecryptVerify(string $armoredCiphertext, string $privateKeyArmored): array
{
    $homedir = sys_get_temp_dir().'/pgp-mailer-decrypt-'.bin2hex(random_bytes(6));
    mkdir($homedir, 0700, true);
    file_put_contents($homedir.'/gpg.conf', "pinentry-mode loopback\ntrust-model always\n");
    file_put_contents($homedir.'/gpg-agent.conf', "allow-loopback-pinentry\n");

    try {
        $g = new gnupg(['home_dir' => $homedir]);
        $g->seterrormode(GNUPG_ERROR_EXCEPTION);

        $imported = $g->import($privateKeyArmored);
        if (! is_array($imported) || empty($imported['fingerprint'])) {
            throw new RuntimeException('Failed to import decryption key');
        }
        $g->adddecryptkey($imported['fingerprint'], '');

        // Try signature-bearing decrypt first; fall back to plain decrypt
        // when the ciphertext is unsigned.
        try {
            $info = $g->decryptverify($armoredCiphertext, $plaintext);

            /** @var array<int, array<string, mixed>> $info */
            return [(string) $plaintext, is_array($info) ? $info : []];
        } catch (Throwable $e) {
            if (! str_contains($e->getMessage(), 'no signature')) {
                throw $e;
            }
        }

        $plaintext = $g->decrypt($armoredCiphertext);
        if (! is_string($plaintext)) {
            throw new RuntimeException('Decryption failed');
        }

        return [$plaintext, []];
    } finally {
        $rm = function (string $p) use (&$rm): void {
            if (! is_dir($p)) {
                return;
            }
            foreach (scandir($p) as $e) {
                if ($e === '.' || $e === '..') {
                    continue;
                }
                $f = $p.'/'.$e;
                is_dir($f) && ! is_link($f) ? $rm($f) : @unlink($f);
            }
            @rmdir($p);
        };
        $rm($homedir);
    }
}
