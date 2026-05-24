<?php

declare(strict_types=1);

return [
    'pgp_key' => [
        'invalid_armor' => 'The :attribute is not a valid OpenPGP public key.',
        'secret_block' => 'The :attribute appears to be a PRIVATE key. Submit only the PUBLIC key block.',
        'expired' => 'The :attribute has expired.',
        'revoked' => 'The :attribute has been revoked.',
        'no_usable_uid' => 'The :attribute has no usable user identifier (UID).',
        'uid_mismatch' => 'The :attribute does not include a UID matching the email address.',
    ],
];
