<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Exceptions;

class MissingSenderKeyException extends PgpMailerException
{
    protected ?string $senderEmail = null;

    public function withSender(?string $email): static
    {
        $this->senderEmail = $email;

        return $this;
    }

    public function context(): array
    {
        $context = parent::context();

        if ($this->senderEmail !== null && $this->senderEmail !== '') {
            $context['sender_email'] = $this->senderEmail;
        }

        return $context;
    }
}
