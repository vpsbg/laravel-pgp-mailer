<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Tests\Stubs;

use Illuminate\Database\Eloquent\Model;

/**
 * Minimal Eloquent model used by the test suite as a Mail recipient.
 */
class User extends Model
{
    protected $guarded = [];

    public $timestamps = true;
}
