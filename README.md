# Undo

Early build. The contract in `contracts/undo` is a thin shell over `crates/undo-core` and `crates/undo-btc`. It has run only in a local sandbox with a mock signer, not against a real signer or any live network, and parts of the planned method list are not built yet. No claim in this repo holds until `CLAIMS.md` lists it with a command.

## Build

Needs Rust with the `wasm32-unknown-unknown` target, `wasm-opt` and Node on `PATH`.

```
scripts/setup-repo.sh     # hooks and git identity, once per clone
scripts/build.sh          # wasm in target/near
scripts/check-wasm.sh     # exports and imports
scripts/check-identity.sh # built wasm and tree
scripts/protocol-check.sh # sandbox suite on protocols 86 and 88, needs NEAR_SANDBOX_BIN_PATH
scripts/shell-mutants.py  # breaks the contract shell one rule at a time and expects a test to notice
```

`tests/REGRESSION-MAP.md` lists each attack-review finding and the test that covers it. `docs/measurements.md` has gas and size.

Always build with `scripts/build.sh`. A plain `cargo build --target wasm32-unknown-unknown` stops with a compile error, because it would lose `--cfg near` and the path remapping.

## License

MIT. Built by Ted Chen with AI coding assistance (Claude).
