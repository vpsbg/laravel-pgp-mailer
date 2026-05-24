<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Engines;

use DateTimeImmutable;
use RuntimeException;
use Throwable;
use Vpsbg\PgpMailer\Exceptions\EncryptionFailedException;
use Vpsbg\PgpMailer\Exceptions\KeyParsingException;
use Vpsbg\PgpMailer\Support\ArmoredKey;
use Vpsbg\PgpMailer\Support\Fingerprint;

/**
 * The package's PGP engine, wrapping the `gnupg` PECL extension (libgpgme).
 *
 * When constructed with $homedir = null, the engine creates a 0700 tempdir
 * for each container resolution (once per request in Laravel) and removes
 * it in its destructor. When given an explicit $homedir, it treats it as
 * host-managed and never deletes it.
 */
class GnupgExtensionEngine
{
    private ?\gnupg $handle = null;

    private readonly string $homedir;

    private readonly bool $ownsHomedir;

    public function __construct(?string $homedir = null)
    {
        if (! extension_loaded('gnupg')) {
            throw new RuntimeException(
                'pgp-mailer: the "gnupg" PECL extension is required. '
                .'Install libgpgme-dev + `pecl install gnupg` + `docker-php-ext-enable gnupg`.'
            );
        }

        if ($homedir === null) {
            $this->homedir = $this->makeEphemeralHomedir();
            $this->ownsHomedir = true;
            $this->writeAgentConfig($this->homedir);
        } else {
            if (! is_dir($homedir) || ! is_writable($homedir)) {
                throw new RuntimeException(
                    "pgp-mailer: configured gnupg homedir [{$homedir}] does not exist or is not writable."
                );
            }
            $this->warnIfHomedirIsLax($homedir);
            $this->homedir = $homedir;
            $this->ownsHomedir = false;
        }
    }

    public function __destruct()
    {
        $this->handle = null;

        if ($this->ownsHomedir) {
            try {
                $this->rmTree($this->homedir);
            } catch (Throwable) {
                // Destructors must not throw; the OS reaps /tmp eventually.
            }
        }
    }

    /**
     * Encrypt (and optionally sign) a payload. Output is ASCII-armored OpenPGP
     * suitable as the second body part of an RFC 3156 multipart/encrypted
     * envelope. When a signing key is supplied, signs-then-encrypts in one
     * operation (the signature is encapsulated inside the ciphertext).
     *
     * @param  list<ArmoredKey>  $recipientKeys
     *
     * @throws EncryptionFailedException
     */
    public function encrypt(
        string $payload,
        array $recipientKeys,
        ?string $signingPrivateKeyArmored = null,
        ?string $signingPassphrase = null,
    ): string {
        if ($recipientKeys === []) {
            throw new EncryptionFailedException('At least one recipient key is required.');
        }

        $signingFpr = null;

        try {
            $g = $this->newHandle();
            // The handle is a long-lived singleton; clear any signer/encrypter
            // state left over from prior calls. Without this, a previously
            // added (and since-scrubbed) signer can fail this call with
            // "invalid signers found".
            $this->resetHandleState($g);
            $g->setarmor(1);

            foreach ($recipientKeys as $key) {
                $fingerprint = $this->importAndExpect($g, $key->armored, false, $key->fingerprint);
                $g->addencryptkey($fingerprint);
            }

            if ($signingPrivateKeyArmored !== null) {
                $signingFpr = $this->importAndExpect($g, $signingPrivateKeyArmored, true);
                $g->addsignkey($signingFpr, $signingPassphrase ?? '');

                $output = $g->encryptsign($payload);
            } else {
                $output = $g->encrypt($payload);
            }

            if (! is_string($output) || $output === '') {
                throw new EncryptionFailedException('gnupg returned empty ciphertext.');
            }

            return $output;
        } catch (EncryptionFailedException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new EncryptionFailedException(
                'PGP encryption failed: '.$e->getMessage(),
                previous: $e,
            );
        } finally {
            // In long-running queue workers the engine singleton outlives
            // the request that imported the signing key. Without this delete,
            // the private key would persist in $homedir/private-keys-v1.d/
            // for the worker's entire lifetime.
            if ($signingFpr !== null) {
                $this->scrubSecret($signingFpr);
            }
        }
    }

    /**
     * Produce a detached armored signature suitable for RFC 3156 multipart/signed.
     *
     * @throws EncryptionFailedException
     */
    public function sign(string $payload, string $signingPrivateKeyArmored, ?string $passphrase = null): string
    {
        $signingFpr = null;

        try {
            $g = $this->newHandle();
            $this->resetHandleState($g);
            $g->setarmor(1);
            $g->setsignmode(GNUPG_SIG_MODE_DETACH);

            $signingFpr = $this->importAndExpect($g, $signingPrivateKeyArmored, true);
            $g->addsignkey($signingFpr, $passphrase ?? '');

            $output = $g->sign($payload);

            if (! is_string($output) || $output === '') {
                throw new EncryptionFailedException('gnupg returned empty signature.');
            }

            return $output;
        } catch (EncryptionFailedException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new EncryptionFailedException(
                'PGP signing failed: '.$e->getMessage(),
                previous: $e,
            );
        } finally {
            if ($signingFpr !== null) {
                $this->scrubSecret($signingFpr);
            }
        }
    }

    /**
     * Parse an ASCII-armored public key block and extract its metadata.
     *
     * @throws KeyParsingException
     */
    public function parsePublicKey(string $armored): ArmoredKey
    {
        // Use a throwaway homedir so importing an untrusted block can't
        // pollute the working keyring (e.g. with a hostile signing subkey
        // shadowing a real one we already imported).
        $scratchDir = $this->makeEphemeralHomedir();

        try {
            $g = $this->newGnupgFor($scratchDir);
            $imported = @$g->import($armored);

            if (! is_array($imported) || empty($imported['fingerprint'])) {
                throw new KeyParsingException('Could not import armored public key block.');
            }

            $fingerprintHex = (string) $imported['fingerprint'];
            $info = $g->keyinfo($fingerprintHex);

            if ($info === []) {
                throw new KeyParsingException('gnupg accepted the import but returned no key info.');
            }

            $key = $info[0];
            $primary = $this->pickPrimarySubkey($key['subkeys'] ?? []);

            if ($primary === null) {
                throw new KeyParsingException('Imported block has no usable subkeys.');
            }

            $uids = $this->extractUidStrings($key['uids'] ?? []);

            $createdAt = isset($primary['timestamp']) && (int) $primary['timestamp'] > 0
                ? (new DateTimeImmutable)->setTimestamp((int) $primary['timestamp'])
                : null;

            $expiresAt = isset($primary['expires']) && (int) $primary['expires'] > 0
                ? (new DateTimeImmutable)->setTimestamp((int) $primary['expires'])
                : null;

            // Newer builds expose `pubkey_algo`; older ones use `algorithm`.
            $algoId = (int) ($primary['pubkey_algo'] ?? $primary['algorithm'] ?? 0);
            $algorithm = $algoId > 0
                ? OpenPgpAlgorithmMap::name(
                    $algoId,
                    isset($primary['length']) ? (int) $primary['length'] : null,
                )
                : null;

            return new ArmoredKey(
                armored: $armored,
                fingerprint: Fingerprint::fromHex($fingerprintHex),
                uids: $uids,
                algorithm: $algorithm,
                createdAt: $createdAt,
                expiresAt: $expiresAt,
                revoked: ! empty($key['disabled']) || ! empty($primary['revoked']),
            );
        } catch (KeyParsingException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new KeyParsingException(
                'gnupg failed to parse public key: '.$e->getMessage(),
                previous: $e,
            );
        } finally {
            try {
                $this->rmTree($scratchDir);
            } catch (Throwable) {
                // best effort
            }
        }
    }

    /**
     * Clear cached signer/encrypter/decrypter lists on a reused handle so a
     * subsequent operation doesn't carry stale state from a previous call.
     * This matters because we delete the secret half of the signing key
     * after each call (see scrubSecret); the next call must re-add it
     * fresh, not see the previous (now-invalid) entry.
     */
    private function resetHandleState(\gnupg $g): void
    {
        // These methods exist on the PECL gnupg extension >= 1.3.0; older
        // builds may not have them. We suppress errors and fall back to a
        // best-effort reset.
        if (method_exists($g, 'clearsignkeys')) {
            @$g->clearsignkeys();
        }
        if (method_exists($g, 'clearencryptkeys')) {
            @$g->clearencryptkeys();
        }
        if (method_exists($g, 'cleardecryptkeys')) {
            @$g->cleardecryptkeys();
        }
    }

    /**
     * Delete the secret half of an imported keypair from the working keyring,
     * leaving the public half (cheap to re-import next call). Best-effort.
     */
    private function scrubSecret(string $fingerprint): void
    {
        try {
            $g = $this->newHandle();
            // Second arg = "allow secret"; without it gpg refuses to delete
            // a key that has a secret half.
            @$g->deletekey($fingerprint, true);
        } catch (Throwable) {
            // see docblock
        }
    }

    private function newHandle(): \gnupg
    {
        if ($this->handle === null) {
            $this->handle = $this->newGnupgFor($this->homedir);
        }

        return $this->handle;
    }

    private function newGnupgFor(string $homedir): \gnupg
    {
        $g = new \gnupg(['home_dir' => $homedir]);
        $g->seterrormode(GNUPG_ERROR_EXCEPTION);

        return $g;
    }

    private function importAndExpect(
        \gnupg $g,
        string $armored,
        bool $expectSecret,
        ?Fingerprint $expected = null,
    ): string {
        $result = @$g->import($armored);

        if (! is_array($result) || empty($result['fingerprint'])) {
            throw new EncryptionFailedException('Failed to import key into gnupg.');
        }

        if ($expectSecret && empty($result['secretimported']) && empty($result['secretunchanged'])) {
            throw new EncryptionFailedException('Expected a private key but the block contained none.');
        }

        $fpr = (string) $result['fingerprint'];

        if ($expected !== null && ! hash_equals(strtoupper($expected->hex), strtoupper($fpr))) {
            throw (new EncryptionFailedException(
                'Recipient key fingerprint mismatch after import.'
            ))->withFingerprint($expected);
        }

        return $fpr;
    }

    /**
     * @param  array<int, array<string, mixed>>  $subkeys
     * @return array<string, mixed>|null
     */
    private function pickPrimarySubkey(array $subkeys): ?array
    {
        foreach ($subkeys as $sub) {
            if (! empty($sub['is_primary'])) {
                return $sub;
            }
        }

        return $subkeys[0] ?? null;
    }

    /**
     * @param  array<int, array<string, mixed>>  $uids
     * @return list<string>
     */
    private function extractUidStrings(array $uids): array
    {
        $out = [];

        foreach ($uids as $uid) {
            if (! empty($uid['revoked']) || ! empty($uid['invalid'])) {
                continue;
            }
            if (isset($uid['uid']) && is_string($uid['uid']) && $uid['uid'] !== '') {
                $out[] = $uid['uid'];
            }
        }

        return $out;
    }

    /**
     * Warn (don't fail) when an operator-supplied homedir has group/world
     * permissions. Secret keys inside such a directory are readable by other
     * UIDs on the host. We don't refuse to run because dedicated-UID setups
     * with multiple FPM workers are a legitimate configuration.
     */
    private function warnIfHomedirIsLax(string $homedir): void
    {
        $stat = @stat($homedir);
        if ($stat === false) {
            return;
        }

        $mode = $stat['mode'] & 0777;
        if (($mode & 0077) !== 0) {
            error_log(sprintf(
                'pgp-mailer: persistent gnupg homedir [%s] has mode %04o; expected 0700. '
                .'Secret keys inside this directory may be readable by other users on this host.',
                $homedir,
                $mode,
            ));
        }
    }

    private function makeEphemeralHomedir(): string
    {
        $base = sys_get_temp_dir();
        $path = $base.DIRECTORY_SEPARATOR.'pgp-mailer-gnupg-'.bin2hex(random_bytes(8));

        if (! mkdir($path, 0700, true) && ! is_dir($path)) {
            throw new RuntimeException("pgp-mailer: could not create gnupg homedir at {$path}");
        }

        @chmod($path, 0700);

        return $path;
    }

    private function writeAgentConfig(string $homedir): void
    {
        // pinentry-mode loopback: gpg-agent 2.1+ otherwise ignores the
        //   passphrase passed via addsignkey().
        // trust-model always: imported recipient keys land at "unknown" trust;
        //   without this gpg refuses to encrypt to them. The host already
        //   admitted them by storing their public key — re-validating trust
        //   here adds no security and just breaks sends.
        @file_put_contents(
            $homedir.DIRECTORY_SEPARATOR.'gpg.conf',
            "pinentry-mode loopback\ntrust-model always\n",
        );
        @file_put_contents(
            $homedir.DIRECTORY_SEPARATOR.'gpg-agent.conf',
            "allow-loopback-pinentry\n",
        );
        @chmod($homedir.DIRECTORY_SEPARATOR.'gpg.conf', 0600);
        @chmod($homedir.DIRECTORY_SEPARATOR.'gpg-agent.conf', 0600);
    }

    private function rmTree(string $path): void
    {
        if (! is_dir($path)) {
            return;
        }

        $entries = scandir($path);
        if ($entries === false) {
            return;
        }

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $full = $path.DIRECTORY_SEPARATOR.$entry;
            if (is_dir($full) && ! is_link($full)) {
                $this->rmTree($full);
            } else {
                @unlink($full);
            }
        }

        @rmdir($path);
    }
}
