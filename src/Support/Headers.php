<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Support;

/**
 * Wire-level header names. All three are stripped before transport so they
 * never reach recipients.
 */
final class Headers
{
    /** Internal marker on the listener's own re-dispatched plaintext copy, to prevent re-entry. */
    public const SKIP = 'X-Pgp-Mailer-Skip';

    /** Caller-controlled opt-out (set via {@see PgpMailer::skip()} or a Mailable's headers()). */
    public const OPT_OUT = 'X-Pgp-Mailer-Disable';

    /** Stamped on the encrypted copy so downstream observers can tell. */
    public const APPLIED = 'X-Pgp-Mailer-Applied';
}
