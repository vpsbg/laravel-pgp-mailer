<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Mime;

use Symfony\Component\Mime\Header\Headers;
use Symfony\Component\Mime\Part\AbstractPart;

/** RFC 3156 §5 detached-signature part (application/pgp-signature). */
final class PgpSignaturePart extends AbstractPart
{
    public function __construct(private readonly string $armored)
    {
        parent::__construct();
    }

    public function bodyToString(): string
    {
        return $this->armored;
    }

    /** @return iterable<string> */
    public function bodyToIterable(): iterable
    {
        yield $this->armored;
    }

    public function getMediaType(): string
    {
        return 'application';
    }

    public function getMediaSubtype(): string
    {
        return 'pgp-signature';
    }

    public function getPreparedHeaders(): Headers
    {
        $headers = parent::getPreparedHeaders();
        $headers->addTextHeader('Content-Transfer-Encoding', '7bit');
        $headers->addTextHeader('Content-Description', 'OpenPGP digital signature');
        $headers->setHeaderBody('Parameterized', 'Content-Disposition', 'attachment');
        $headers->setHeaderParameter('Content-Disposition', 'filename', 'signature.asc');

        return $headers;
    }
}
