<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Exceptions;

use Exception;
use Vpsbg\PgpMailer\Support\Fingerprint;

class PgpMailerException extends Exception
{
    protected ?string $recipientEmail = null;

    protected ?Fingerprint $fingerprint = null;

    public function withRecipient(?string $email): static
    {
        $this->recipientEmail = $email;

        return $this;
    }

    public function withFingerprint(?Fingerprint $fingerprint): static
    {
        $this->fingerprint = $fingerprint;

        return $this;
    }

    /**
     * Laravel calls this when logging the exception. Carries diagnostic
     * metadata WITHOUT ever exposing message body or key material.
     *
     * @return array<string, string>
     */
    public function context(): array
    {
        return array_filter([
            'recipient_email' => $this->recipientEmail,
            'fingerprint' => $this->fingerprint?->longKeyId(),
        ], fn ($v): bool => $v !== null && $v !== '');
    }
}
