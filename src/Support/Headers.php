<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Support;

/**
 * Wire-level header names. OPT_OUT, NO_ENCRYPT, and VISIBLE_SUBJECT are
 * stripped before transport so they never reach recipients. APPLIED is
 * intentionally left on the wire so downstream tooling (mail logs, audit
 * pipelines, transport middleware) can detect that PGP was applied.
 */
final class Headers
{
    /** Caller-controlled "bypass PGP entirely" (set via {@see PgpMailer::skip()} or a Mailable's headers()). */
    public const OPT_OUT = 'X-Pgp-Mailer-Disable';

    /**
     * Caller-controlled "do not encrypt this message" (set via
     * {@see PgpMailer::unencrypted()} or a Mailable's headers()). The
     * message is still signed if signing is configured globally.
     */
    public const NO_ENCRYPT = 'X-Pgp-Mailer-No-Encrypt';

    /**
     * Caller-controlled "keep the outer Subject visible for this message"
     * (set via {@see PgpMailer::withVisibleSubject()} or a Mailable's
     * headers()). Only meaningful when protected_headers.enabled is true;
     * otherwise a no-op.
     */
    public const VISIBLE_SUBJECT = 'X-Pgp-Mailer-Visible-Subject';

    /** Stamped on the PGP-processed copy so downstream observers can tell. Stays on the wire. */
    public const APPLIED = 'X-Pgp-Mailer-Applied';
}
