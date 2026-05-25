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
use Vpsbg\PgpMailer\Events\PgpSigningApplied;
use Vpsbg\PgpMailer\Exceptions\EncryptionFailedException;
use Vpsbg\PgpMailer\Exceptions\MissingRecipientKeyException;
use Vpsbg\PgpMailer\Exceptions\MissingSenderKeyException;
use Vpsbg\PgpMailer\Mime\PgpSignedPart;
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

it('signs (does not encrypt) when no recipient has a key under sign_only policy', function (): void {
    PgpKey::query()->delete();
    config()->set('pgp-mailer.missing_key_policy', 'sign_only');

    Mail::to($this->recipientEmail)->send(new PlainMailable('sign-only body'));

    $sent = sentMessages();
    expect($sent)->toHaveCount(1);

    $serialized = $sent[0]->getOriginalMessage()->toString();
    expect($serialized)->toContain('multipart/signed');
    expect($serialized)->toContain('sign-only body');
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

it('encrypts to Bcc recipients too', function (): void {
    Mail::to('nobody-with-no-key@example.com')
        ->bcc($this->recipientEmail)
        ->send(new PlainMailable('bcc test payload'));

    // Mixed audience + default sign_only+split_recipients → encrypt for
    // the keyed Bcc, re-dispatch a multipart/signed copy for the rest.
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

it('default engine_failure_policy halts the send when encryption throws', function (): void {
    bindThrowingEngine();
    Event::fake([PgpEncryptionFailed::class]);

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

// === SignOnly mode =====================================================
//
// When signing is configured and a recipient has no key, the listener
// should produce a multipart/signed body rather than plaintext. This is
// the central upgrade introduced alongside the X-Pgp-Mailer-No-Encrypt
// opt-out.

it('signs when recipient has no key and signing is configured', function (): void {
    PgpKey::query()->delete();
    config()->set('pgp-mailer.missing_key_policy', 'sign_only');

    Event::fake([PgpSigningApplied::class, PgpEncryptionApplied::class]);

    Mail::to($this->recipientEmail)->send(new PlainMailable('sign-only body'));

    $sent = sentMessages();
    expect($sent)->toHaveCount(1);

    $email = $sent[0]->getOriginalMessage();
    $serialized = $email->toString();

    expect($serialized)->toContain('multipart/signed');
    expect($serialized)->toContain('protocol="application/pgp-signature"');
    expect($serialized)->toContain('micalg=pgp-sha256');
    expect($serialized)->toContain('-----BEGIN PGP SIGNATURE-----');
    // Body is in the clear because the message isn't encrypted.
    expect($serialized)->toContain('sign-only body');

    Event::assertDispatched(PgpSigningApplied::class);
    Event::assertNotDispatched(PgpEncryptionApplied::class);

    // Cryptographic round-trip: detached signature verifies against the
    // signed body bytes.
    expect(verifyDetached($email, $this->keys['private']))->toBeTrue();
});

it('listener is a no-op when signing is not configured', function (): void {
    // Even with a recipient key present, the listener short-circuits when
    // signing isn't configured globally — the package only operates in
    // sign-only or sign+encrypt modes, so without signing it does nothing.
    config()->set('pgp-mailer.signing.enabled', false);
    config()->set('pgp-mailer.signing.key', null);

    Mail::to($this->recipientEmail)->send(new PlainMailable('cleartext payload'));

    $sent = sentMessages();
    expect($sent)->toHaveCount(1);

    $serialized = $sent[0]->getOriginalMessage()->toString();
    expect($serialized)->not->toContain('multipart/signed');
    expect($serialized)->not->toContain('multipart/encrypted');
    expect($serialized)->toContain('cleartext payload');
    expect($serialized)->not->toContain('X-Pgp-Mailer-Applied');
});

// === Split-recipients path with signing ================================
//
// Mixed audience + passthrough+split + signing configured: the keyed
// portion gets encrypted-and-signed; the unkeyed portion gets a separate
// multipart/signed copy (not plaintext).

it('encrypts to keyed recipients and signs the copy to unkeyed', function (): void {
    config()->set('pgp-mailer.missing_key_policy', 'sign_only');

    Mail::to('nobody-with-no-key@example.com')
        ->bcc($this->recipientEmail)
        ->send(new PlainMailable('split signed payload'));

    $sent = sentMessages();
    expect(count($sent))->toBe(2);

    $encrypted = null;
    $signed = null;
    foreach ($sent as $msg) {
        $s = $msg->getOriginalMessage()->toString();
        if (str_contains($s, 'multipart/encrypted')) {
            $encrypted = $msg->getOriginalMessage();
        } elseif (str_contains($s, 'multipart/signed')) {
            $signed = $msg->getOriginalMessage();
        }
    }

    expect($encrypted)->not->toBeNull('expected one encrypted message for the keyed recipient');
    expect($signed)->not->toBeNull('expected one signed-only message for the unkeyed recipient');

    expect($signed->toString())->toContain('split signed payload');
    expect($signed->toString())->not->toContain('X-Pgp-Mailer-No-Encrypt');
});

it('falls back to one signed message for everyone when split_recipients is disabled', function (): void {
    config()->set('pgp-mailer.missing_key_policy', 'sign_only');
    config()->set('pgp-mailer.sign_only.split_recipients', false);

    Mail::to('nobody-with-no-key@example.com')
        ->bcc($this->recipientEmail)
        ->send(new PlainMailable('mixed audience payload'));

    $sent = sentMessages();
    expect(count($sent))->toBe(1);

    $serialized = $sent[0]->getOriginalMessage()->toString();
    expect($serialized)->toContain('multipart/signed');
    expect($serialized)->not->toContain('multipart/encrypted');
    expect($serialized)->toContain('mixed audience payload');
});

// === X-Pgp-Mailer-No-Encrypt opt-out ===================================

it('PgpMailer::unencrypted produces multipart/signed when signing is configured', function (): void {
    $mailable = new PlainMailable('unencrypted but signed');

    Mail::to($this->recipientEmail)->send(PgpMailer::unencrypted($mailable));

    $sent = sentMessages();
    expect($sent)->toHaveCount(1);

    $serialized = $sent[0]->getOriginalMessage()->toString();
    expect($serialized)->toContain('multipart/signed');
    expect($serialized)->not->toContain('multipart/encrypted');
    expect($serialized)->toContain('unencrypted but signed');
    expect($serialized)->not->toContain('X-Pgp-Mailer-No-Encrypt');
});

it('PgpMailer::unencrypted is a no-op (and strips the header) when signing is off', function (): void {
    // With no signing configured the listener is a no-op end-to-end, so
    // ::unencrypted() effectively collapses into ::skip(). We still strip
    // the opt-out header from the outgoing message either way.
    config()->set('pgp-mailer.signing.enabled', false);
    config()->set('pgp-mailer.signing.key', null);

    Mail::to($this->recipientEmail)->send(PgpMailer::unencrypted(new PlainMailable('plain announcement')));

    $sent = sentMessages();
    expect($sent)->toHaveCount(1);

    $serialized = $sent[0]->getOriginalMessage()->toString();
    expect($serialized)->not->toContain('multipart/signed');
    expect($serialized)->not->toContain('multipart/encrypted');
    expect($serialized)->toContain('plain announcement');
    expect($serialized)->not->toContain('X-Pgp-Mailer-No-Encrypt');
});

it('PgpMailer::unencrypted returns the same Mailable instance', function (): void {
    $mailable = new PlainMailable('whatever');

    expect(PgpMailer::unencrypted($mailable))->toBe($mailable);
});

it('honors X-Pgp-Mailer-No-Encrypt set via raw header on the message', function (): void {
    // Recipient HAS a key, but the message asked for no encryption.
    Mail::raw('header-driven announcement', function ($message): void {
        $message->to($this->recipientEmail);
        $message->subject('opt-out-encrypt');
        $message->getSymfonyMessage()->getHeaders()->addTextHeader('X-Pgp-Mailer-No-Encrypt', '1');
    });

    $serialized = sentMessages()[0]->getOriginalMessage()->toString();
    expect($serialized)->toContain('multipart/signed');
    expect($serialized)->not->toContain('multipart/encrypted');
    expect($serialized)->toContain('header-driven announcement');
    expect($serialized)->not->toContain('X-Pgp-Mailer-No-Encrypt');
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

// === Per-sender signing keys ===========================================
//
// signing.senders lets a host pair From addresses to distinct signing
// keys, so support@app is signed by the support key and billing@app by
// the billing key. Lookups fall back to the scalar default or apply
// signing.unmatched_sender_policy.

it('signs with the per-sender key that matches the From address', function (): void {
    $alt = $this->fixtureAltKeys();
    $altEmail = $this->fixtureAltEmail();

    config()->set('pgp-mailer.signing.enabled', true);
    config()->set('pgp-mailer.signing.key', null);
    config()->set('pgp-mailer.signing.senders', [
        $altEmail => ['key' => $alt['private']],
    ]);

    Mail::raw('per-sender signed body', function ($m) use ($altEmail): void {
        $m->from($altEmail);
        $m->to($this->recipientEmail);
        $m->subject('per-sender');
    });

    $serialized = sentMessages()[0]->getOriginalMessage()->toString();
    [$plaintext, $info] = gnupgDecryptVerify(
        extractArmoredCiphertext($serialized),
        $this->keys['private'],
        [$alt['public']],
    );

    expect($plaintext)->toContain('per-sender signed body');
    expect($info)->not->toBeEmpty();
    // Signer fingerprint MUST be the alt key's, not the recipient's.
    expect(strtoupper((string) $info[0]['fingerprint']))
        ->toBe('A244A8EBB89975334876F26B5B7779EBB683C76D');
});

it('matches From addresses case-insensitively against signing.senders', function (): void {
    $alt = $this->fixtureAltKeys();

    config()->set('pgp-mailer.signing.enabled', true);
    config()->set('pgp-mailer.signing.key', null);
    config()->set('pgp-mailer.signing.senders', [
        'Support@Example.com' => ['key' => $alt['private']],
    ]);

    Mail::raw('case test', function ($m): void {
        $m->from('SUPPORT@EXAMPLE.COM');
        $m->to($this->recipientEmail);
        $m->subject('case');
    });

    [$plaintext, $info] = gnupgDecryptVerify(
        extractArmoredCiphertext(sentMessages()[0]->getOriginalMessage()->toString()),
        $this->keys['private'],
        [$alt['public']],
    );

    expect($plaintext)->toContain('case test');
    expect(strtoupper((string) $info[0]['fingerprint']))
        ->toBe('A244A8EBB89975334876F26B5B7779EBB683C76D');
});

it('falls back to the default signing key when From has no senders entry (use_default)', function (): void {
    config()->set('pgp-mailer.signing.enabled', true);
    config()->set('pgp-mailer.signing.key', $this->keys['private']);
    config()->set('pgp-mailer.signing.senders', [
        'support@example.com' => ['key' => $this->fixtureAltKeys()['private']],
    ]);
    config()->set('pgp-mailer.signing.unmatched_sender_policy', 'use_default');

    Mail::raw('default fallback body', function ($m): void {
        $m->from('someone-else@example.com');
        $m->to($this->recipientEmail);
        $m->subject('default fallback');
    });

    [, $info] = gnupgDecryptVerify(
        extractArmoredCiphertext(sentMessages()[0]->getOriginalMessage()->toString()),
        $this->keys['private'],
    );

    // Signed by the default key (== recipient key in this test, fpr 5C86...).
    expect(strtoupper((string) $info[0]['fingerprint']))
        ->toBe('5C86E8EFCD946F05FDCC99A3F6AD4E436EB07FD0');
});

it('is a no-op for senders without a key under unmatched_sender_policy=skip', function (): void {
    // unmatched_sender_policy=skip is an explicit operator opt-in to "do
    // nothing for senders not in the per-sender map." Since encryption
    // requires signing, the listener falls all the way through and the
    // message goes out untouched — even when the recipient has a key.
    config()->set('pgp-mailer.signing.enabled', true);
    config()->set('pgp-mailer.signing.key', null);
    config()->set('pgp-mailer.signing.senders', [
        'support@example.com' => ['key' => $this->keys['private']],
    ]);
    config()->set('pgp-mailer.signing.unmatched_sender_policy', 'skip');

    Mail::raw('skip-signing body', function ($m): void {
        $m->from('orphan@example.com');
        $m->to($this->recipientEmail);
        $m->subject('skip');
    });

    $sent = sentMessages();
    expect($sent)->toHaveCount(1);

    $serialized = $sent[0]->getOriginalMessage()->toString();
    expect($serialized)->not->toContain('multipart/encrypted');
    expect($serialized)->not->toContain('multipart/signed');
    expect($serialized)->toContain('skip-signing body');
});

it('throws MissingSenderKeyException under unmatched_sender_policy=fail', function (): void {
    config()->set('pgp-mailer.signing.enabled', true);
    config()->set('pgp-mailer.signing.key', null);
    config()->set('pgp-mailer.signing.senders', [
        'support@example.com' => ['key' => $this->keys['private']],
    ]);
    config()->set('pgp-mailer.signing.unmatched_sender_policy', 'fail');

    expect(function (): void {
        Mail::raw('would never send', function ($m): void {
            $m->from('orphan@example.com');
            $m->to($this->recipientEmail);
            $m->subject('fail');
        });
    })->toThrow(MissingSenderKeyException::class);

    expect(sentMessages())->toHaveCount(0);
});

it('preserves the legacy single-key install when senders is empty', function (): void {
    // The pre-existing test "signs when signing is enabled in config" already
    // covers this, but assert the new resolver path is transparent: with no
    // senders entries and a scalar key, every From signs with the scalar.
    config()->set('pgp-mailer.signing.enabled', true);
    config()->set('pgp-mailer.signing.key', $this->keys['private']);
    config()->set('pgp-mailer.signing.senders', []);

    Mail::raw('legacy single-key', function ($m): void {
        $m->from('whoever@example.com');
        $m->to($this->recipientEmail);
        $m->subject('legacy');
    });

    [, $info] = gnupgDecryptVerify(
        extractArmoredCiphertext(sentMessages()[0]->getOriginalMessage()->toString()),
        $this->keys['private'],
    );

    expect(strtoupper((string) $info[0]['fingerprint']))
        ->toBe('5C86E8EFCD946F05FDCC99A3F6AD4E436EB07FD0');
});

// === Protected Headers (encrypted Subject) =============================

it('replaces outer Subject with the configured placeholder and embeds the real Subject in the encrypted body', function (): void {
    config()->set('pgp-mailer.protected_headers.enabled', true);

    Mail::to($this->recipientEmail)->send(new PlainMailable('protected body'));

    $email = sentMessages()[0]->getOriginalMessage();
    expect($email->getSubject())->toBe('Encrypted Subject');

    $recovered = recoverEncrypted($email->toString(), $this->keys['private']);
    expect($recovered)->toContain('Subject: Test');
    expect($recovered)->toContain('protected body');
});

it('marks the inner encrypted part with protected-headers=v1 so Thunderbird swaps the Subject', function (): void {
    config()->set('pgp-mailer.protected_headers.enabled', true);

    Mail::to($this->recipientEmail)->send(new PlainMailable('payload'));

    $recovered = recoverEncrypted(
        sentMessages()[0]->getOriginalMessage()->toString(),
        $this->keys['private'],
    );

    // Order of parameters on Content-Type is not guaranteed; match either.
    expect($recovered)->toMatch('/Content-Type:[^\r\n]*protected-headers="?v1"?/');
});

it('marks the inner signed part with protected-headers=v1 on the sign-only path', function (): void {
    PgpKey::query()->delete();
    config()->set('pgp-mailer.missing_key_policy', 'sign_only');
    config()->set('pgp-mailer.protected_headers.enabled', true);

    Mail::to($this->recipientEmail)->send(new PlainMailable('payload'));

    $serialized = sentMessages()[0]->getOriginalMessage()->toString();
    expect($serialized)->toMatch('/Content-Type:[^\r\n]*protected-headers="?v1"?/');
});

it('does not emit the v1 marker when the visible-subject opt-out is used', function (): void {
    config()->set('pgp-mailer.protected_headers.enabled', true);

    $mailable = new PlainMailable('payload');
    Mail::to($this->recipientEmail)->send(PgpMailer::withVisibleSubject($mailable));

    $recovered = recoverEncrypted(
        sentMessages()[0]->getOriginalMessage()->toString(),
        $this->keys['private'],
    );

    expect($recovered)->not->toContain('protected-headers');
});

it('respects a custom placeholder_subject', function (): void {
    config()->set('pgp-mailer.protected_headers.enabled', true);
    config()->set('pgp-mailer.protected_headers.placeholder_subject', '[Encrypted Message]');

    Mail::to($this->recipientEmail)->send(new PlainMailable('payload'));

    $email = sentMessages()[0]->getOriginalMessage();
    expect($email->getSubject())->toBe('[Encrypted Message]');

    expect(recoverEncrypted($email->toString(), $this->keys['private']))
        ->toContain('Subject: Test');
});

it('also protects Subject on the sign-only path when recipient has no key', function (): void {
    PgpKey::query()->delete();
    config()->set('pgp-mailer.missing_key_policy', 'sign_only');
    config()->set('pgp-mailer.protected_headers.enabled', true);

    Mail::to($this->recipientEmail)->send(new PlainMailable('sign-only body'));

    $email = sentMessages()[0]->getOriginalMessage();
    expect($email->getSubject())->toBe('Encrypted Subject');

    // Body is cleartext between the multipart/signed boundaries — the inner
    // Subject header is visible in the serialized output.
    $serialized = $email->toString();
    expect($serialized)->toContain('multipart/signed');
    expect($serialized)->toContain('Subject: Test');
    expect($serialized)->toContain('sign-only body');
});

it('keeps the outer Subject visible per-message via the X-Pgp-Mailer-Visible-Subject header', function (): void {
    config()->set('pgp-mailer.protected_headers.enabled', true);

    Mail::raw('payload', function ($m): void {
        $m->to($this->recipientEmail);
        $m->subject('Invoice #4242');
        $m->getSymfonyMessage()->getHeaders()->addTextHeader('X-Pgp-Mailer-Visible-Subject', '1');
    });

    $email = sentMessages()[0]->getOriginalMessage();
    expect($email->getSubject())->toBe('Invoice #4242');
    expect($email->toString())->not->toContain('X-Pgp-Mailer-Visible-Subject');
});

it('PgpMailer::withVisibleSubject keeps the outer Subject visible', function (): void {
    config()->set('pgp-mailer.protected_headers.enabled', true);

    $mailable = new PlainMailable('payload');
    Mail::to($this->recipientEmail)->send(PgpMailer::withVisibleSubject($mailable));

    $email = sentMessages()[0]->getOriginalMessage();
    expect($email->getSubject())->toBe('Test');
    expect($email->toString())->not->toContain('X-Pgp-Mailer-Visible-Subject');
});

it('PgpMailer::withVisibleSubject returns the same Mailable instance', function (): void {
    $mailable = new PlainMailable('whatever');

    expect(PgpMailer::withVisibleSubject($mailable))->toBe($mailable);
});

it('does not touch the outer Subject when protected_headers is disabled (default)', function (): void {
    Mail::to($this->recipientEmail)->send(new PlainMailable('payload'));

    expect(sentMessages()[0]->getOriginalMessage()->getSubject())->toBe('Test');
});

it('strips the visible-subject opt-out header even when protected_headers is disabled', function (): void {
    Mail::raw('payload', function ($m): void {
        $m->to($this->recipientEmail);
        $m->subject('Invoice #4242');
        $m->getSymfonyMessage()->getHeaders()->addTextHeader('X-Pgp-Mailer-Visible-Subject', '1');
    });

    expect(sentMessages()[0]->getOriginalMessage()->toString())
        ->not->toContain('X-Pgp-Mailer-Visible-Subject');
});

it('protects Subject on the secondary signed copy in the split-recipients path', function (): void {
    config()->set('pgp-mailer.protected_headers.enabled', true);
    config()->set('pgp-mailer.missing_key_policy', 'sign_only');
    config()->set('pgp-mailer.sign_only.split_recipients', true);

    Mail::to('nobody-with-no-key@example.com')
        ->bcc($this->recipientEmail)
        ->send(new PlainMailable('split payload'));

    $sent = sentMessages();
    expect(count($sent))->toBeGreaterThanOrEqual(2);

    foreach ($sent as $msg) {
        $email = $msg->getOriginalMessage();
        expect($email->getSubject())->toBe('Encrypted Subject');
    }

    $signedCopy = null;
    foreach ($sent as $msg) {
        if (str_contains($msg->getOriginalMessage()->toString(), 'multipart/signed')) {
            $signedCopy = $msg->getOriginalMessage();
            break;
        }
    }
    expect($signedCopy)->not->toBeNull();
    expect($signedCopy->toString())->toContain('Subject: Test');
});

it('does not rewrite the outer Subject when the listener is a no-op (signing disabled)', function (): void {
    config()->set('pgp-mailer.protected_headers.enabled', true);
    config()->set('pgp-mailer.signing.enabled', false);

    Mail::to($this->recipientEmail)->send(new PlainMailable('payload'));

    expect(sentMessages()[0]->getOriginalMessage()->getSubject())->toBe('Test');
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
 * Verify the detached PGP signature on a multipart/signed Email. Returns
 * true when the signature verifies against the signed body bytes. Uses the
 * in-memory Symfony parts (not the serialized output) so we sign exactly
 * what Symfony will emit between the boundaries.
 */
function verifyDetached(Email $email, string $privateKeyArmored): bool
{
    $body = $email->getBody();
    if (! $body instanceof PgpSignedPart) {
        throw new RuntimeException('Email body is not a PgpSignedPart');
    }

    [$signedPart, $sigPart] = $body->getParts();
    $signedBytes = $signedPart->toString();
    $signatureArmor = $sigPart->bodyToString();

    $homedir = sys_get_temp_dir().'/pgp-mailer-verify-'.bin2hex(random_bytes(6));
    mkdir($homedir, 0700, true);
    file_put_contents($homedir.'/gpg.conf', "pinentry-mode loopback\ntrust-model always\n");
    file_put_contents($homedir.'/gpg-agent.conf', "allow-loopback-pinentry\n");

    try {
        $g = new gnupg(['home_dir' => $homedir]);
        $g->seterrormode(GNUPG_ERROR_EXCEPTION);
        $g->import($privateKeyArmored);
        $info = $g->verify($signedBytes, $signatureArmor);

        return is_array($info) && $info !== [] && ! empty($info[0]['fingerprint']);
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

/**
 * Decrypt with the gnupg PECL extension in a throwaway homedir. Returns
 * [plaintext, signaturesInfo]. signaturesInfo is empty when the ciphertext
 * isn't signed; non-empty (one entry per signer) when it is.
 *
 * Pass `$extraPublicKeysArmored` to import additional public keys into the
 * verifier's keyring — needed when the message was signed by a key that is
 * not the recipient's own private key.
 *
 * @param  list<string>  $extraPublicKeysArmored
 * @return array{0: string, 1: array<int, array<string, mixed>>}
 */
function gnupgDecryptVerify(string $armoredCiphertext, string $privateKeyArmored, array $extraPublicKeysArmored = []): array
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

        foreach ($extraPublicKeysArmored as $pub) {
            $g->import($pub);
        }

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
