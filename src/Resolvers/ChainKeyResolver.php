<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Resolvers;

use Vpsbg\PgpMailer\Contracts\KeyResolver;
use Vpsbg\PgpMailer\Support\ArmoredKey;

/**
 * Composes an ordered list of KeyResolvers. forEmail returns the first
 * non-null. forEmails passes only the still-unresolved emails to each
 * subsequent link — so a 100-recipient batch where the local DB resolves
 * 99 hits the remote resolver with just the one straggler.
 */
class ChainKeyResolver implements KeyResolver
{
    /** @var list<KeyResolver> */
    private array $resolvers;

    /** @param  iterable<KeyResolver>  $resolvers */
    public function __construct(iterable $resolvers)
    {
        $list = [];
        foreach ($resolvers as $resolver) {
            $list[] = $resolver;
        }
        $this->resolvers = $list;
    }

    public function forEmail(string $email): ?ArmoredKey
    {
        foreach ($this->resolvers as $resolver) {
            $key = $resolver->forEmail($email);
            if ($key !== null) {
                return $key;
            }
        }

        return null;
    }

    public function forEmails(iterable $emails): array
    {
        $remaining = [];
        foreach ($emails as $email) {
            $normalized = strtolower(trim($email));
            if ($normalized !== '') {
                $remaining[$normalized] = true;
            }
        }

        $result = [];
        foreach ($this->resolvers as $resolver) {
            if ($remaining === []) {
                break;
            }

            $found = $resolver->forEmails(array_keys($remaining));
            foreach ($found as $email => $key) {
                $result[$email] = $key;
                unset($remaining[$email]);
            }
        }

        return $result;
    }
}
