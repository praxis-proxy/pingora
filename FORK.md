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

The 0.11.0 release moves the base to upstream `main`
at 4487f7b, five commits past 0.9.0. Those commits
make the response body and trailer filters on
`ProxyHttp` async (every implementation has to
follow), parameterize downstream sessions, add an
owned HTTP test origin, and abort TLS offload tasks
when they are dropped.

## Changes From Upstream

The fork is based on upstream `main` at 4487f7b
(0.9.0 plus the five commits above) with seven
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

### 4. Provider-agnostic rustls backend

`pingora-rustls` no longer depends on `ring` and
installs no rustls `CryptoProvider`; rustls'
`custom-provider` feature makes a missing install a
loud failure instead of a silent default. The
application chooses the provider and installs it
before any service is constructed. This is what lets
Praxis run all cryptography in the RHEL OpenSSL FIPS
provider. Upstream still hardcodes `ring`.
`pingora-s2n` is untouched.

**Files:** `pingora-rustls/`,
`pingora-core/src/connectors/tls/rustls/mod.rs`,
`pingora-core/src/listeners/tls/rustls/mod.rs`

### 5. Extended Master Secret on upstream TLS 1.2

Every upstream `ClientConfig` the rustls connector
builds sets `require_ems` (RFC 7627), which NIST
SP 800-52r2 requires and without which rustls reports
a config as not FIPS.

**Files:** `pingora-core/src/connectors/tls/rustls/mod.rs`

### 6. Vendored rustls-openssl provider

`pingora-rustls-openssl/` is
[tofay/rustls-openssl][rustls-openssl] (MIT) at 0.4.1
plus its pull request #44, which routes the last
legacy OpenSSL calls through the EVP provider APIs so
they reach the FIPS module and adds the
`SigningKey::public_key` override Praxis needs to
load certificates. It is published as
`quixotic-plecostomus-rustls-openssl` with the
`rustls_openssl` library name unchanged. The copy is
a snapshot; commit-level history stays upstream.
When upstream releases those changes Praxis switches
back and the copy is removed.

### 7. Abandoned TLS handshakes log at debug

A client that connects and hangs up before the TLS
handshake finishes (a Kubernetes TCP probe, a load
balancer health check, a port scanner) is logged at
`debug` instead of `error`. Real failures, such as
protocol errors, received alerts, missing client
certificates and the handshake timeout, still log at
`error`. To tell them apart, the rustls server
handshake keeps the underlying `io::Error` as the
error's cause instead of flattening it into the
context string. Only the rustls backend does this;
boringssl, openssl and s2n are unchanged.

A client that rejects the server certificate and
disconnects without sending an alert looks the same
as a probe, so it also logs at `debug`. Upstream
still logs every failed downstream handshake at
`error`.

**Files:** `pingora-core/src/services/listening.rs`,
`pingora-core/src/protocols/tls/rustls/server.rs`,
`pingora-core/src/protocols/tls/rustls/stream.rs`

The fork also carries dependency-hygiene changes:
dropping the unmaintained `derivative` crate,
replacing the archived `serde_yaml` with `yaml_serde`,
and modernizing `dashmap`, `rand`, `x509-parser`, and
`indexmap`/`blake2`. All remaining commits are CI and
fork infrastructure scaffolding.

## Crate Naming

The fork is published to crates.io as
`quixotic-plecostomus-*` (22 pingora crates plus the
vendored `quixotic-plecostomus-rustls-openssl`; the
upstream `pingora-test-utils` crate stays unpublished
and path-only). The name was
chosen to avoid appearing in search results for
"Pingora" or "Praxis", since the fork is temporary
and not intended for external use.

Each crate preserves `[lib] name = "pingora_*"` so
that consumer source code requires zero changes -
only `Cargo.toml` package aliasing is needed:

```toml
pingora-core = {
    version = "0.11.0",
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
| **Base** | upstream `main` at 4487f7b (0.9.0 + 5 commits) |
| **License** | Apache 2.0 (unchanged from upstream) |
| **crates.io** | `quixotic-plecostomus-*` v0.11.0 (pingora crates); `quixotic-plecostomus-rustls-openssl` v0.4.1 |

[upstream]: https://github.com/cloudflare/pingora
[rustls-openssl]: https://github.com/tofay/rustls-openssl
[pr726]: https://github.com/cloudflare/pingora/pull/726
[pr908]: https://github.com/cloudflare/pingora/pull/908
