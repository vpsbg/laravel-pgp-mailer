<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Mail\Events\MessageSending;
use Illuminate\Support\Facades\Event;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;
use Vpsbg\PgpMailer\Console\GenerateAppKey;
use Vpsbg\PgpMailer\Contracts\KeyResolver;
use Vpsbg\PgpMailer\Engines\GnupgExtensionEngine;
use Vpsbg\PgpMailer\Listeners\EncryptOutgoingMail;

class PgpMailerServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('pgp-mailer')
            ->hasConfigFile()
            ->hasMigration('create_pgp_keys_table')
            ->hasCommand(GenerateAppKey::class);
    }

    public function registeringPackage(): void
    {
        $this->app->singleton(GnupgExtensionEngine::class, function (Application $app): GnupgExtensionEngine {
            $homedir = $app->make(ConfigRepository::class)->get('pgp-mailer.gnupg_homedir');

            return new GnupgExtensionEngine(is_string($homedir) && $homedir !== '' ? $homedir : null);
        });

        $this->app->singleton(KeyResolver::class, function (Application $app) {
            $class = (string) $app->make(ConfigRepository::class)->get('pgp-mailer.resolver');

            return $app->make($class);
        });
    }

    public function packageBooted(): void
    {
        if ($this->app->runningInConsole()) {
            // Short-form publish tags, in addition to the prefixed
            // `pgp-mailer-config` / `pgp-mailer-migrations` tags registered by
            // spatie/laravel-package-tools. Lets the user run
            //   php artisan vendor:publish --provider="..." --tag="config"
            // which is the convention used by many ecosystem packages.
            $this->publishes([
                __DIR__.'/../config/pgp-mailer.php' => config_path('pgp-mailer.php'),
            ], 'config');

            $this->publishes([
                __DIR__.'/../database/migrations/create_pgp_keys_table.php.stub' => database_path(
                    'migrations/'.date('Y_m_d_His').'_create_pgp_keys_table.php'
                ),
            ], 'migrations');
        }

        if (! $this->app->make(ConfigRepository::class)->get('pgp-mailer.enabled', true)) {
            return;
        }

        Event::listen(MessageSending::class, EncryptOutgoingMail::class);
    }
}
