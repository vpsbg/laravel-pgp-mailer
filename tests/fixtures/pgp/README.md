# Test PGP fixtures

Throwaway RSA-2048 keypair used by the engine tests. **Zero value outside the
suite** — the UID points at a non-existent domain, and the private key was
never used to sign or encrypt anything outside this repository.

| File | What it is |
|---|---|
| `recipient-public.asc` | Public key with UID `Gnupg Smoke <gnupg-smoke@test.local>`. RSA-2048 sign primary + RSA-2048 encrypt subkey (the shape real PGP clients produce; gpg refuses to encrypt to sign-only keys). |
| `recipient-private.asc` | Matching private key, **no passphrase**. |
| `signer-alt-public.asc` | A second, distinct keypair with UID `Gnupg Smoke Alt <gnupg-smoke-alt@test.local>`. Used by the per-sender signing tests so we can prove a given outbound message was signed with the alt key (its fingerprint differs from the recipient key's). |
| `signer-alt-private.asc` | Matching private key, **no passphrase**. |

To regenerate the recipient pair:

```bash
TMP=$(mktemp -d) && chmod 700 "$TMP"
cat > "$TMP/batch.in" <<EOF
%no-protection
Key-Type: RSA
Key-Length: 2048
Key-Usage: sign
Subkey-Type: RSA
Subkey-Length: 2048
Subkey-Usage: encrypt
Name-Real: Gnupg Smoke
Name-Email: gnupg-smoke@test.local
Expire-Date: 0
%commit
EOF
GNUPGHOME=$TMP gpg --batch --gen-key "$TMP/batch.in"
FPR=$(GNUPGHOME=$TMP gpg --list-keys --with-colons | awk -F: '/^fpr:/{print $10; exit}')
GNUPGHOME=$TMP gpg --armor --export        "$FPR" > recipient-public.asc
GNUPGHOME=$TMP gpg --armor --export-secret-keys "$FPR" > recipient-private.asc
```

The alt signer pair is generated the same way; substitute `Name-Real: Gnupg Smoke Alt`
and `Name-Email: gnupg-smoke-alt@test.local`, write to `signer-alt-*.asc`.
