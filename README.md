# Cumulus Vault

Encrypted, verifiable backups to Filecoin for small organizations.

Cumulus Vault is an open-source command-line tool from Infinitum Corporation®. It encrypts files on your machine, stores them on Filecoin (or a local folder), and keeps a tamper-evident log that proves each backup can still be restored. It is built for small businesses, nonprofits and newsrooms that need ransomware-resistant backups without trusting a storage provider with plaintext.

## Features

- **Client-side encryption.** ChaCha20-Poly1305, applied in 1 MiB authenticated chunks. Truncated or altered archives are rejected.
- **Filecoin storage.** The Lighthouse onramp stores data on Filecoin; a local content-addressed backend works offline and for tests.
- **Tamper-evident ledger.** An append-only, SHA-256 hash-chained log of every backup and verification.
- **Restore drills.** `cvault verify` re-downloads, decrypts and checks a backup against its recorded digest, then logs the result.
- **Bitcoin anchoring.** `cvault anchor` timestamps the ledger head with OpenTimestamps, so anyone can check with the standard `ots` client that the backup history was not rewritten later.
- **Safe restore.** Extraction blocks path traversal and special files.

## Quick start

```bash
pip install git+https://github.com/InfinitumCorp/cumulus-vault
cvault init                      # creates ~/.cumulus-vault/vault.key (back this up offline)
cvault backup ./documents        # local backend by default
cvault verify                    # ledger check + test restore
cvault restore ./restored
cvault log
cvault anchor                    # Bitcoin timestamp of the ledger head (OpenTimestamps)
```

### Filecoin backend

```bash
export LIGHTHOUSE_API_KEY=...    # never commit this
cvault --backend lighthouse backup ./documents
cvault --backend lighthouse verify
```

## Archive format

`CVAULT01 | salt(16) | base_nonce(8) | [len(4) | ciphertext]...` - chunk *i* uses nonce `base_nonce || i`. The last chunk is bound with associated data `final`, which makes truncation detectable.

## Roadmap

1. Scheduled backups and retention policies
2. Direct Filecoin deals and PDP proof-of-data-possession checks
3. Multi-recipient keys (age/X25519) and key escrow for organizations
4. Signed verification reports for auditors and insurers

## Development

```bash
pip install -e '.[dev]'
pytest
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

Contact: info@infinitumcorporation.ai - https://infinitumcorporation.ai/
