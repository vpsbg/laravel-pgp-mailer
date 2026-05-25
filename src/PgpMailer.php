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

    /**
     * Mark this Mailable instance to be signed but NOT encrypted, even when
     * the recipients have stored PGP keys. Useful for signed newsletters or
     * public announcements where confidentiality isn't required but
     * authenticity is. If signing isn't configured globally, the listener
     * is a no-op and this call has the same effect as {@see skip()}.
     *
     * Returns the same instance so it composes inline:
     *
     *     Mail::to($u)->send(PgpMailer::unencrypted(new NewsletterMail($data)));
     */
    public static function unencrypted(Mailable $mailable): Mailable
    {
        $mailable->withSymfonyMessage(function (Email $message): void {
            $message->getHeaders()->addTextHeader(Headers::NO_ENCRYPT, '1');
        });

        return $mailable;
    }

    /**
     * Mark this Mailable instance to keep its outer Subject visible on the
     * wire even when `protected_headers.enabled` is true globally. Useful
     * for transactional mail where the Subject must remain searchable /
     * threadable for recipients whose MUAs don't understand memory-hole
     * headers. No-op when protected headers are disabled in config.
     *
     * Returns the same instance so it composes inline:
     *
     *     Mail::to($u)->send(PgpMailer::withVisibleSubject(new InvoiceMail($data)));
     */
    public static function withVisibleSubject(Mailable $mailable): Mailable
    {
        $mailable->withSymfonyMessage(function (Email $message): void {
            $message->getHeaders()->addTextHeader(Headers::VISIBLE_SUBJECT, '1');
        });

        return $mailable;
    }
}
