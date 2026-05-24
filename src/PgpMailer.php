<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer;

use Illuminate\Mail\Mailable;
use Symfony\Component\Mime\Email;
use Vpsbg\PgpMailer\Support\Headers;

final class PgpMailer
{
    /**
     * Mark this Mailable instance to skip PGP encryption. Use for Mailables
     * you don't own (third-party packages). For Mailables you own, declare
     * the bypass header in the Mailable's own headers() method — that's
     * the idiomatic path and needs no package import.
     *
     * Returns the same instance so it composes inline:
     *
     *     Mail::to($u)->send(PgpMailer::skip(new ThirdPartyMail($data)));
     *
     * Safe under queueing — withSymfonyMessage callbacks survive Mailable
     * serialization.
     */
    public static function skip(Mailable $mailable): Mailable
    {
        $mailable->withSymfonyMessage(function (Email $message): void {
            $message->getHeaders()->addTextHeader(Headers::OPT_OUT, '1');
        });

        return $mailable;
    }
}
