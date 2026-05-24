<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Mime;

use Symfony\Component\Mime\Header\Headers;
use Symfony\Component\Mime\Part\AbstractMultipartPart;

/** RFC 3156 §4 multipart/encrypted body. */
final class PgpEncryptedPart extends AbstractMultipartPart
{
    public function getMediaSubtype(): string
    {
        return 'encrypted';
    }

    public function getPreparedHeaders(): Headers
    {
        $headers = parent::getPreparedHeaders();
        $headers->setHeaderParameter('Content-Type', 'protocol', 'application/pgp-encrypted');

        return $headers;
    }
}
