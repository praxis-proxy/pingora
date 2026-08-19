fn main() {
    let vendored = std::env::var("CARGO_FEATURE_VENDORED").is_ok();
    let system = std::env::var("CARGO_FEATURE_SYSTEM").is_ok();
    if vendored && system {
        panic!(
            "The `vendored` and `system` features of pingora-openssl are mutually exclusive. \
             Disable the `vendored` feature to link against system OpenSSL. \
             You may need to set OPENSSL_DIR (or OPENSSL_LIB_DIR + OPENSSL_INCLUDE_DIR) \
             to point to your OpenSSL installation."
        );
    }
}
