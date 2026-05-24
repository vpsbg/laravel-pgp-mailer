<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Mime;

use Symfony\Component\Mime\Part\AbstractPart;

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

    /**
     * Wrap a body part and a detached armored signature in the RFC 3156 §5
     * multipart/signed envelope. The caller is responsible for computing
     * the signature over $signedBody->toString() so that the bytes signed
     * are bytewise identical to the bytes that travel between the boundaries.
     */
    public static function wrapSigned(
        AbstractPart $signedBody,
        string $detachedSignatureArmor,
        string $micalg = 'pgp-sha256',
    ): PgpSignedPart {
        return new PgpSignedPart(
            $signedBody,
            new PgpSignaturePart($detachedSignatureArmor),
            $micalg,
        );
    }
}
