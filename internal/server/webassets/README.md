# Browser crypto assets

The `/x/:id` decrypt page loads these pinned, same-origin builds:

- `libsodium` and `libsodium-wrappers` 0.7.10 for XChaCha20-Poly1305
- `hash-wasm` 4.9.0's Argon2 UMD build for gated-link Argon2id

They are vendored rather than loaded from a CDN so a share recipient's fragment
key and plaintext stay inside code shipped by the aqt server. The original MIT
and ISC license texts are stored alongside the assets.

Source package SHA-512 digests:

- `libsodium@0.7.10`: `798fb3ee10eb0cac6400af9029954dbfdd80e4a624c5fbc8b21b412649a0e534a20a762a64fde2f4e3bdc2113bf4fc209b88c66a81e090ce1aa3f6fd0b2bb8cd`
- `libsodium-wrappers@0.7.10`: `a4edc5d50f4d3cb07f3162217a18a6e366ff1706f7d09352702361f13710fe421cfaa18b41c87c6a0f306f491e2b710fe646c66a49351fc5b0a3bbfedfaacd42`
- `hash-wasm@4.9.0`: `ed25bb7a3c9f9d1c6e39cee9b501d27f82c3a196963a2bdfceac3ee6ba5c424bb49c77e689c3ca139d6b6bd06244b0264fcfa018b7acb6bd57ae8524a9d8cbeb`
