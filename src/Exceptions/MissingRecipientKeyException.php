<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Exceptions;

class MissingRecipientKeyException extends PgpMailerException
{
    /** @var list<string> */
    protected array $missingEmails = [];

    /** @param  list<string>  $emails */
    public function withMissingEmails(array $emails): static
    {
        $this->missingEmails = $emails;

        return $this;
    }

    public function context(): array
    {
        return [
            ...parent::context(),
            'missing_emails' => implode(',', $this->missingEmails),
        ];
    }
}
