---
name: dumer-vault-crypto
description: Implement D.U.M.E.R storage security — SQLCipher DB, key hierarchy (DEK wrapped by OS key, Argon2id KEK, separate vault key), AEAD vault items, placeholder substitution, canary tokens, TTL cache, export/delete. Use for any persistence of personal or sensitive data.
---
# Vault & crypto
- Use vetted crates only (RustCrypto/`ring`-class); never invent primitives. Verify current versions/APIs.
- DB: SQLCipher; random 256-bit DEK wrapped by DPAPI/TPM-backed key (Windows) or Secret Service/TPM (Linux); optional Argon2id passphrase KEK.
- Vault items: XChaCha20-Poly1305 under a separate vault key released after user verification; auto-lock timer; zeroize on lock.
- Memory records carry source, timestamp, confidence, sensitivity, retention, provenance, taint. Deletion cascades to embeddings, caches, replicas.
- Placeholders: model sees `{{PROFILE.field}}`; broker substitutes at execution into per-field allowlisted destinations only. Vault use = tier 3.
- Canary secrets in vault/profile/files; any hit in egress/model output/logs ⇒ alert + pause the pipeline.
- No secrets in argv/env/logs/crash dumps; `secrecy`/`zeroize`; disable core dumps for sensitive processes; log-scan test in CI.
- Tests: wrong key, rotation, migration, restart, export, deletion cascade, TTL expiry, lock/unlock, canary trip.
