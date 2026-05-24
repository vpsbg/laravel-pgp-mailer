<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Contracts;

enum UnmatchedSenderPolicy: string
{
    case UseDefault = 'use_default';
    case Skip = 'skip';
    case Fail = 'fail';

    public static function fromConfig(?string $value): self
    {
        return self::tryFrom((string) $value) ?? self::UseDefault;
    }
}
