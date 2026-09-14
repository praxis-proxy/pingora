# Pingora Fork

This repository is a fork of
[Cloudflare Pingora][upstream] maintained by the
Praxis project. The fork is intended to be temporary.

## Why the Fork Exists

Upstream Pingora does not expose all of the TLS
customization hooks and proxy body handling that
Praxis requires. Upstream review cycles are slow,
making it impractical to wait for changes to be
accepted before shipping Praxis releases.

Syncing onto upstream **0.9.0** also pulls in native
peer-certificate handshake callbacks for the rustls
backend ([cloudflare/pingora#908][pr908]), which let
Praxis read a peer's SPIFFE identity during
mutual-TLS handshakes. Earlier releases handed the
rustls handshake-complete callback an empty
certificate reference, unlike the boringssl and
openssl backends.

## Changes From Upstream

The fork is based on upstream **0.9.0** with three
functional changes:

### 1. Custom rustls `ServerConfig` support

Adds `TlsSettings::with_server_config()` for
injecting a fully built rustls `ServerConfig` (0-RTT,
session resumption, custom certificate resolvers).
Adapted from the approach proposed in
[cloudflare/pingora#726][pr726].

Upstream 0.9.0 added a related but distinct
`Acceptor::from_server_config()`. The fork keeps
`TlsSettings::with_server_config()` so existing Praxis
call sites need no changes.

**Files:** `pingora-core/src/listeners/tls/rustls/mod.rs`

### 2. Certificate parsing (`WrappedX509::parse`)

Adds `WrappedX509::parse()` for per-cluster CA
verification, enabling Praxis to load and verify
certificates for individual upstream clusters.

**Files:** `pingora-core/src/utils/tls/rustls.rs`,
`pingora-core/src/utils/tls/s2n.rs`

### 3. Downstream body forwarding fix

Triggers initial body send when the downstream
connection has already consumed data, fixing a proxy
body forwarding edge case.

**Files:** `pingora-proxy/src/proxy_custom.rs`,
`pingora-proxy/src/proxy_h1.rs`,
`pingora-proxy/src/proxy_h2.rs`

The fork also carries dependency-hygiene changes:
dropping the unmaintained `derivative` crate,
replacing the archived `serde_yaml` with `yaml_serde`,
and modernizing `dashmap`, `rand`, `x509-parser`, and
`indexmap`/`blake2`. All remaining commits are CI and
fork infrastructure scaffolding.

## Crate Naming

The fork is published to crates.io as
`quixotic-plecostomus-*` (22 crates). The name was
chosen to avoid appearing in search results for
"Pingora" or "Praxis", since the fork is temporary
and not intended for external use.

Each crate preserves `[lib] name = "pingora_*"` so
that consumer source code requires zero changes -
only `Cargo.toml` package aliasing is needed:

```toml
pingora-core = {
    version = "0.9.0",
    package = "quixotic-plecostomus-core",
}
```

## Upstream Plan

The plan is to contribute the remaining changes
upstream and eliminate this fork. The `ServerConfig`
change already has a related upstream PR
([cloudflare/pingora#726][pr726]). If upstream does
not accept the changes, we will document the
divergence formally and maintain this fork as a
first-class dependency with clear provenance.

## Provenance

| | |
|---|---|
| **Upstream** | https://github.com/cloudflare/pingora |
| **Org fork** | https://github.com/praxis-proxy/pingora |
| **Base tag** | 0.9.0 |
| **License** | Apache 2.0 (unchanged from upstream) |
| **crates.io** | `quixotic-plecostomus-*` v0.9.0 |

[upstream]: https://github.com/cloudflare/pingora
[pr726]: https://github.com/cloudflare/pingora/pull/726
[pr908]: https://github.com/cloudflare/pingora/pull/908
