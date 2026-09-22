> **Praxis fork.** This directory is a vendored copy of
> [tofay/rustls-openssl](https://github.com/tofay/rustls-openssl) at 0.4.1 plus
> its pull request #44 (routing the last legacy OpenSSL calls through the EVP
> provider APIs so they reach the RHEL FIPS module, and the `SigningKey::public_key`
> override). It is published as `quixotic-plecostomus-rustls-openssl` with the
> library name `rustls_openssl` unchanged. It is a snapshot; commit-level history stays in the
> upstream repository. Once upstream releases those changes, praxis switches
> back and this copy goes away. See `FORK.md` at the repository root.

# rustls-openssl
A [rustls Crypto Provider](https://docs.rs/rustls/latest/rustls/crypto/struct.CryptoProvider.html) that uses OpenSSL for cryptographic operations.

[Documentation](https://docs.rs/rustls-openssl).

[![crates.io](https://img.shields.io/crates/v/rustls-openssl?style=flat-square&logo=rust)](https://crates.io/crates/rustls-openssl)
[![Build Status](https://github.com/tofay/rustls-openssl/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/tofay/rustls-openssl/actions/workflows/ci.yml?query=branch%3Amain)
[![Documentation](https://docs.rs/rustls-openssl/badge.svg)](https://docs.rs/rustls-openssl/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Coverage Status (codecov.io)](https://codecov.io/gh/tofay/rustls-openssl/branch/main/graph/badge.svg)](https://codecov.io/gh/tofay/rustls-openssl/)
