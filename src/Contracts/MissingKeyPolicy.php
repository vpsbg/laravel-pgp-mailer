<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Contracts;

enum MissingKeyPolicy: string
{
    case Passthrough = 'passthrough';
    case Fail = 'fail';
    case Drop = 'drop';
    case LogOnly = 'log_only';

    public static function fromConfig(?string $value): self
    {
        return self::tryFrom((string) $value) ?? self::Passthrough;
    }
}
