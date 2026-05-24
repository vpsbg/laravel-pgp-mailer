<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Mime;

use Symfony\Component\Mime\Header\Headers;
use Symfony\Component\Mime\Part\AbstractMultipartPart;
use Symfony\Component\Mime\Part\AbstractPart;

/** RFC 3156 §5 multipart/signed body. */
final class PgpSignedPart extends AbstractMultipartPart
{
    public function __construct(
        AbstractPart $signedBody,
        PgpSignaturePart $signature,
        private readonly string $micalg = 'pgp-sha256',
    ) {
        parent::__construct($signedBody, $signature);
    }

    public function getMediaSubtype(): string
    {
        return 'signed';
    }

    public function getPreparedHeaders(): Headers
    {
        $headers = parent::getPreparedHeaders();
        $headers->setHeaderParameter('Content-Type', 'protocol', 'application/pgp-signature');
        $headers->setHeaderParameter('Content-Type', 'micalg', $this->micalg);

        return $headers;
    }
}
