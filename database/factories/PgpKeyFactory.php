<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Database\Factories;

use Illuminate\Database\Eloquent\Factories\Factory;
use Vpsbg\PgpMailer\Models\PgpKey;

/**
 * @extends Factory<PgpKey>
 */
class PgpKeyFactory extends Factory
{
    protected $model = PgpKey::class;

    public function definition(): array
    {
        return [
            'email' => fake()->unique()->safeEmail(),
            'public_key' => "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nfake\n-----END PGP PUBLIC KEY BLOCK-----\n",
            'fingerprint' => strtoupper(bin2hex(random_bytes(20))),
            'algorithm' => 'rsa2048',
            'key_created_at' => now()->subDays(30),
            'expires_at' => null,
            'revoked_at' => null,
            'last_verified_at' => now(),
            'uid_mismatch_at' => null,
        ];
    }

    public function revoked(): static
    {
        return $this->state(['revoked_at' => now()]);
    }

    public function expired(): static
    {
        return $this->state(['expires_at' => now()->subDay()]);
    }

    public function uidMismatched(): static
    {
        return $this->state(['uid_mismatch_at' => now()]);
    }
}
