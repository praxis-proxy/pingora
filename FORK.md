# Pingora Fork

This repository is a fork of
[Cloudflare Pingora][upstream] maintained by the
Praxis project. The fork is intended to be temporary.

## Why the Fork Exists

Upstream Pingora does not expose the TLS
customization hooks and proxy body handling that
Praxis requires. Upstream review cycles are slow,
making it impractical to wait for changes to be
accepted before shipping Praxis releases.

## Changes From Upstream

The fork is based on upstream **v0.8.2** with three
functional changes:

### 1. Custom rustls `ServerConfig` support

Allows injecting a custom rustls `ServerConfig` for
0-RTT, session resumption, and custom certificate
resolvers. Adapted from the approach proposed in
[cloudflare/pingora#726][pr726].

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

All other commits are CI and fork infrastructure
scaffolding.

## Crate Naming

The fork is published to crates.io as
`quixotic-plecostomus-*` (21 crates). The name was
chosen to avoid appearing in search results for
"Pingora" or "Praxis", since the fork is temporary
and not intended for external use.

Each crate preserves `[lib] name = "pingora_*"` so
that consumer source code requires zero changes -
only `Cargo.toml` package aliasing is needed:

```toml
pingora-core = {
    version = "0.8.2",
    package = "quixotic-plecostomus-core",
}
```

## Upstream Plan

The plan is to contribute all three changes upstream
and eliminate this fork. The `ServerConfig` change
already has a related upstream PR
([cloudflare/pingora#726][pr726]). If upstream does
not accept the changes, we will document the
divergence formally and maintain this fork as a
first-class dependency with clear provenance.

## Provenance

| | |
|---|---|
| **Upstream** | https://github.com/cloudflare/pingora |
| **Org fork** | https://github.com/praxis-proxy/pingora |
| **Base tag** | v0.8.2 |
| **License** | Apache 2.0 (unchanged from upstream) |
| **crates.io** | `quixotic-plecostomus-*` v0.8.2 |

[upstream]: https://github.com/cloudflare/pingora
[pr726]: https://github.com/cloudflare/pingora/pull/726
