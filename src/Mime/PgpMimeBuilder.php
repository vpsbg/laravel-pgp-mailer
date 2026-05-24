<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Mime;

/**
 * Wraps an armored OpenPGP message in the RFC 3156 two-part body. The
 * listener only replaces Message::$body, never the headers, so From/To/Cc/
 * Bcc/Subject/Date/Message-ID survive untouched.
 */
final class PgpMimeBuilder
{
    public static function wrap(string $armoredCiphertext): PgpEncryptedPart
    {
        return new PgpEncryptedPart(
            new PgpVersionPart,
            new PgpCiphertextPart($armoredCiphertext),
        );
    }
}
