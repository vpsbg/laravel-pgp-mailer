<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Console;

use Illuminate\Console\Command;

/**
 * Prints a `gpg --batch` recipe to generate the application's sender signing
 * keypair. The package itself never needs the `gpg` CLI at runtime — this is
 * a setup-ergonomics command, not a runtime dependency.
 */
class GenerateAppKey extends Command
{
    public $signature = 'pgp-mailer:keypair
        {--name= : Real name embedded in the key UID}
        {--email= : Email embedded in the key UID}
        {--bits=4096 : RSA key length}
        {--expire=2y : Expiry (gpg syntax: 0=never, 30d, 1y, 2y)}
        {--out= : Output directory for the .asc files (default: storage/pgp/)}';

    public $description = 'Print a gpg recipe to generate the sender signing keypair used by laravel-pgp-mailer.';

    public function handle(): int
    {
        $name = $this->stringOption('name', 'Application Signing Key');
        $email = $this->stringOption('email', 'noreply@example.com');
        $bits = (int) $this->stringOption('bits', '4096');
        $expire = $this->stringOption('expire', '2y');
        $out = $this->stringOption('out', '') ?: storage_path('pgp');

        $this->line('');
        $this->info('Run the following on a host that has GnuPG installed:');
        $this->line('');

        $this->line('  mkdir -p '.escapeshellarg($out));
        $this->line('');
        $this->line("  gpg --batch --gen-key <<'EOF'");
        $this->line('  %no-protection');
        $this->line('  Key-Type: RSA');
        $this->line("  Key-Length: {$bits}");
        $this->line('  Subkey-Type: RSA');
        $this->line("  Subkey-Length: {$bits}");
        $this->line("  Name-Real: {$name}");
        $this->line("  Name-Email: {$email}");
        $this->line("  Expire-Date: {$expire}");
        $this->line('  EOF');
        $this->line('');
        $this->line('  # Then export, replacing <fpr> with the printed fingerprint:');
        $this->line('  gpg --armor --export-secret-keys <fpr> > '.$out.'/signing-private.asc');
        $this->line('  gpg --armor --export        <fpr> > '.$out.'/signing-public.asc');
        $this->line('  chmod 600 '.$out.'/signing-private.asc');
        $this->line('');
        $this->info('Then point your .env at the private key:');
        $this->line('');
        $this->line('  PGP_MAIL_SIGN=true');
        $this->line('  PGP_MAIL_SIGNING_KEY_PATH='.$out.'/signing-private.asc');
        $this->line('  PGP_MAIL_SIGNING_KEY_PASSPHRASE=    # blank if you used %no-protection');
        $this->line('');
        $this->comment('Note: %no-protection above creates a key with no passphrase — appropriate');
        $this->comment('for a service signing key whose file permissions are the access control.');
        $this->comment('For a passphrase-protected key, omit that line and set the env var.');
        $this->line('');

        return self::SUCCESS;
    }

    private function stringOption(string $name, string $default): string
    {
        $value = $this->option($name);

        return is_string($value) && $value !== '' ? $value : $default;
    }
}
