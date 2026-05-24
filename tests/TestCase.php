<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Tests;

use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Support\Facades\Schema;
use Orchestra\Testbench\TestCase as Orchestra;
use Vpsbg\PgpMailer\PgpMailerServiceProvider;
use Vpsbg\PgpMailer\Tests\Stubs\User;

class TestCase extends Orchestra
{
    protected function setUp(): void
    {
        parent::setUp();

        Factory::guessFactoryNamesUsing(
            fn (string $modelName) => 'Vpsbg\\PgpMailer\\Database\\Factories\\'.class_basename($modelName).'Factory'
        );

        // Persistent in-memory SQLite — drop and recreate per test for isolation.
        Schema::dropIfExists('pgp_keys');
        Schema::dropIfExists('users');

        $migration = include __DIR__.'/../database/migrations/create_pgp_keys_table.php.stub';
        $migration->up();

        Schema::create('users', function ($table): void {
            $table->id();
            $table->string('email');
            $table->timestamps();
        });

        // Observers persist across tests; clear so each starts empty.
        User::flushEventListeners();
    }

    protected function getPackageProviders($app): array
    {
        return [
            PgpMailerServiceProvider::class,
        ];
    }

    public function getEnvironmentSetUp($app): void
    {
        config()->set('database.default', 'testing');
        config()->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);
        config()->set('cache.default', 'array');
        config()->set('mail.default', 'array');
        config()->set('mail.mailers.array', ['transport' => 'array']);

        config()->set('auth.providers.users.model', User::class);
    }

    /** @return array{public: string, private: string} */
    protected function fixtureKeys(): array
    {
        return [
            'public' => file_get_contents(__DIR__.'/fixtures/pgp/recipient-public.asc'),
            'private' => file_get_contents(__DIR__.'/fixtures/pgp/recipient-private.asc'),
        ];
    }

    protected function fixtureEmail(): string
    {
        return 'gnupg-smoke@test.local';
    }
}
