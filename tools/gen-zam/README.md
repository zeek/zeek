# Gen-ZAM, a templator for the Zeek Abstract Machine

Zeek uses the `gen-zam` tool during its build, to synthesize operations in ZAM,
the Zeek Abstract Machine. The main reason for why you might want to use this
repository on its own is cross-compilation, for which you'll need `gen-zam` on
the build host, much like `bifcl` and `binpac`.
