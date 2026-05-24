<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Mime;

use Symfony\Component\Mime\Header\Headers;
use Symfony\Component\Mime\Part\AbstractPart;

/** The application/octet-stream part carrying the armored ciphertext. */
final class PgpCiphertextPart extends AbstractPart
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
        return 'octet-stream';
    }

    public function getPreparedHeaders(): Headers
    {
        $headers = parent::getPreparedHeaders();
        $headers->addTextHeader('Content-Transfer-Encoding', '7bit');
        $headers->addTextHeader('Content-Description', 'OpenPGP encrypted message');
        $headers->setHeaderBody('Parameterized', 'Content-Disposition', 'inline');
        $headers->setHeaderParameter('Content-Disposition', 'filename', 'encrypted.asc');

        return $headers;
    }
}
