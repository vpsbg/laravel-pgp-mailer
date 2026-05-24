<?php

declare(strict_types=1);

namespace Vpsbg\PgpMailer\Tests\Stubs;

use Illuminate\Mail\Mailable;
use Illuminate\Mail\Mailables\Content;
use Illuminate\Mail\Mailables\Envelope;

/**
 * Minimal Mailable used only by the listener test suite.
 */
class PlainMailable extends Mailable
{
    public function __construct(public string $body) {}

    public function envelope(): Envelope
    {
        return new Envelope(subject: 'Test');
    }

    public function content(): Content
    {
        return new Content(htmlString: '<p>'.e($this->body).'</p>');
    }
}
