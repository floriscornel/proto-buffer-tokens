# proto-buffer-tokens

This is a **work-in-progress** implementation of [Protocol Buffer Tokens](https://fly.io/blog/api-tokens-a-tedious-survey/#protocol-buffer-tokens-the-anti-paseto) in Rust.

The goal is to create a library that can sign and verify tokens using Ed25519. The tokens are encoded and decoded using Protocol Buffers to reduce the token length.