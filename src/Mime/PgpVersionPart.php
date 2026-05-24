<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Mime;

use Symfony\Component\Mime\Header\Headers;
use Symfony\Component\Mime\Part\AbstractPart;

/** RFC 3156 §4 "Version: 1" identification part. Always 7-bit ASCII. */
final class PgpVersionPart extends AbstractPart
{
    private const BODY = "Version: 1\r\n";

    public function bodyToString(): string
    {
        return self::BODY;
    }

    /** @return iterable<string> */
    public function bodyToIterable(): iterable
    {
        yield self::BODY;
    }

    public function getMediaType(): string
    {
        return 'application';
    }

    public function getMediaSubtype(): string
    {
        return 'pgp-encrypted';
    }

    public function getPreparedHeaders(): Headers
    {
        $headers = parent::getPreparedHeaders();
        $headers->addTextHeader('Content-Transfer-Encoding', '7bit');
        $headers->addTextHeader('Content-Description', 'PGP/MIME version identification');

        return $headers;
    }
}
