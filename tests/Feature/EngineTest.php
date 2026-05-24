<?php

declare(strict_types=1);

use Vpsbg\PgpMailer\Engines\GnupgExtensionEngine;
use Vpsbg\PgpMailer\Exceptions\EncryptionFailedException;

beforeEach(function (): void {
    $this->engine = new GnupgExtensionEngine;
    $this->publicArmored = file_get_contents(__DIR__.'/../fixtures/pgp/recipient-public.asc');
    $this->privateArmored = file_get_contents(__DIR__.'/../fixtures/pgp/recipient-private.asc');
    $this->publicKey = $this->engine->parsePublicKey($this->publicArmored);
});

it('parses the fixture public key with sane metadata', function (): void {
    expect($this->publicKey->fingerprint->hex)->toHaveLength(40)
        ->and($this->publicKey->uids)->not->toBeEmpty()
        ->and($this->publicKey->algorithm)->toStartWith('rsa');
});

it('encrypts and round-trips back to byte-identical payload', function (): void {
    $payload = "Subject: secret\r\n\r\nthe payload, including\nmultiple lines and \"quotes\".\n";

    $ciphertext = $this->engine->encrypt($payload, [$this->publicKey]);

    expect($ciphertext)->toContain('-----BEGIN PGP MESSAGE-----');

    [$recovered] = gnupgDecryptVerify($ciphertext, $this->privateArmored);
    expect($recovered)->toBe($payload);
});

it('signs and encrypts; signature is reported on decrypt-verify', function (): void {
    $payload = "the inner message\n";

    $ciphertext = $this->engine->encrypt(
        $payload,
        [$this->publicKey],
        $this->privateArmored,
        null,
    );

    [$recovered, $info] = gnupgDecryptVerify($ciphertext, $this->privateArmored);

    expect($recovered)->toBe($payload);
    expect($info)->not->toBeEmpty();
});

it('throws when no recipients are given', function (): void {
    $this->engine->encrypt('payload', []);
})->throws(EncryptionFailedException::class, 'recipient');

// Security: the signing private key must not linger in the keyring after
// a sign call returns. In long-running queue workers the engine singleton
// outlives the request that imported the key.

it('removes the signing secret from the keyring after encrypt+sign', function (): void {
    $homedir = sys_get_temp_dir().'/pgp-mailer-test-'.bin2hex(random_bytes(6));
    mkdir($homedir, 0700, true);
    file_put_contents($homedir.'/gpg.conf', "pinentry-mode loopback\ntrust-model always\n");
    file_put_contents($homedir.'/gpg-agent.conf', "allow-loopback-pinentry\n");

    try {
        $engine = new GnupgExtensionEngine($homedir);

        $ciphertext = $engine->encrypt('inner', [$this->publicKey], $this->privateArmored, null);
        expect($ciphertext)->toContain('-----BEGIN PGP MESSAGE-----');

        $probe = new gnupg(['home_dir' => $homedir]);
        $probe->seterrormode(GNUPG_ERROR_EXCEPTION);
        foreach ($probe->keyinfo('') as $key) {
            expect($key['is_secret'] ?? false)
                ->toBeFalse('signing private key was not scrubbed from the keyring');
        }
    } finally {
        rmHomedir($homedir);
    }
});

it('removes the signing secret from the keyring after detached sign', function (): void {
    $homedir = sys_get_temp_dir().'/pgp-mailer-test-'.bin2hex(random_bytes(6));
    mkdir($homedir, 0700, true);
    file_put_contents($homedir.'/gpg.conf', "pinentry-mode loopback\ntrust-model always\n");
    file_put_contents($homedir.'/gpg-agent.conf', "allow-loopback-pinentry\n");

    try {
        $engine = new GnupgExtensionEngine($homedir);
        $signature = $engine->sign('payload', $this->privateArmored, null);
        expect($signature)->toContain('-----BEGIN PGP SIGNATURE-----');

        $probe = new gnupg(['home_dir' => $homedir]);
        $probe->seterrormode(GNUPG_ERROR_EXCEPTION);
        foreach ($probe->keyinfo('') as $key) {
            expect($key['is_secret'] ?? false)
                ->toBeFalse('signing private key was not scrubbed from the keyring');
        }
    } finally {
        rmHomedir($homedir);
    }
});

function rmHomedir(string $p): void
{
    if (! is_dir($p)) {
        return;
    }
    foreach (scandir($p) as $e) {
        if ($e === '.' || $e === '..') {
            continue;
        }
        $f = $p.'/'.$e;
        is_dir($f) && ! is_link($f) ? rmHomedir($f) : @unlink($f);
    }
    @rmdir($p);
}
