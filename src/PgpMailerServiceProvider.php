<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer;

use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Mail\Events\MessageSending;
use Illuminate\Support\Facades\Event;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;
use Vpsbg\PgpMailer\Contracts\KeyResolver;
use Vpsbg\PgpMailer\Contracts\SigningKeyResolver;
use Vpsbg\PgpMailer\Engines\GnupgExtensionEngine;
use Vpsbg\PgpMailer\Listeners\EncryptOutgoingMail;
use Vpsbg\PgpMailer\Resolvers\ChainKeyResolver;
use Vpsbg\PgpMailer\Resolvers\ConfigSigningKeyResolver;
use Vpsbg\PgpMailer\Resolvers\KeyserverKeyResolver;

class PgpMailerServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('pgp-mailer')
            ->hasConfigFile()
            ->hasTranslations()
            ->hasMigration('create_pgp_keys_table');
    }

    public function registeringPackage(): void
    {
        $this->app->singleton(GnupgExtensionEngine::class, function (Application $app): GnupgExtensionEngine {
            $homedir = $app->make(ConfigRepository::class)->get('pgp-mailer.gnupg_homedir');

            return new GnupgExtensionEngine(is_string($homedir) && $homedir !== '' ? $homedir : null);
        });

        $this->app->singleton(KeyResolver::class, function (Application $app) {
            $config = $app->make(ConfigRepository::class);
            $innerClass = (string) $config->get('pgp-mailer.resolver');
            $inner = $app->make($innerClass);

            if (! (bool) $config->get('pgp-mailer.keyserver.enabled', false)) {
                return $inner;
            }

            return new ChainKeyResolver([
                $inner,
                $app->make(KeyserverKeyResolver::class),
            ]);
        });

        $this->app->singleton(SigningKeyResolver::class, function (Application $app): SigningKeyResolver {
            $class = $app->make(ConfigRepository::class)->get('pgp-mailer.signing.resolver');

            return $app->make(is_string($class) && $class !== '' ? $class : ConfigSigningKeyResolver::class);
        });
    }

    public function packageBooted(): void
    {
        if ($this->app->runningInConsole()) {
            // Short-form `config` / `migrations` / `translations` publish tags
            // in addition to the prefixed `pgp-mailer-config` /
            // `pgp-mailer-migrations` / `pgp-mailer-translations` tags
            // registered by spatie/laravel-package-tools.
            $this->publishes([
                __DIR__.'/../config/pgp-mailer.php' => config_path('pgp-mailer.php'),
            ], 'config');

            $this->publishes([
                __DIR__.'/../database/migrations/create_pgp_keys_table.php.stub' => database_path(
                    'migrations/'.date('Y_m_d_His').'_create_pgp_keys_table.php'
                ),
            ], 'migrations');

            $this->publishes([
                __DIR__.'/../resources/lang' => $this->app->langPath('vendor/pgp-mailer'),
            ], 'translations');
        }

        if (! $this->app->make(ConfigRepository::class)->get('pgp-mailer.enabled', true)) {
            return;
        }

        Event::listen(MessageSending::class, EncryptOutgoingMail::class);
    }
}
