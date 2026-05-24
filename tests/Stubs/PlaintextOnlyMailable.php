<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Tests\Stubs;

use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;
use Illuminate\Mail\Mailables\Headers;

/**
 * Demonstrates the recommended opt-out path: a Mailable declares the bypass
 * header in its own `headers()` builder. No wrapping required at the call
 * site — `Mail::to(...)->send(new PlaintextOnlyMailable(...))` flows the
 * header straight to the listener, which honors it and strips it.
 */
class PlaintextOnlyMailable extends Mailable
{
    public function __construct(public string $body) {}

    public function envelope(): Envelope
    {
        return new Envelope(subject: 'Newsletter');
    }

    public function content(): Content
    {
        return new Content(htmlString: '<p>'.e($this->body).'</p>');
    }

    public function headers(): Headers
    {
        return new Headers(text: [
            'X-Pgp-Mailer-Disable' => '1',
        ]);
    }
}
