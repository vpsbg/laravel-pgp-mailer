<?php

arch('it will not use debugging functions')
    ->expect(['dd', 'dump', 'ray'])
    ->each->not->toBeUsed();

arch('keyserver resolver routes through the HTTP factory not the Http facade')
    ->expect('Vpsbg\PgpMailer\Resolvers\KeyserverKeyResolver')
    ->not->toUse('Illuminate\Support\Facades\Http');
