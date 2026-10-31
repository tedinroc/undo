;; Control for scripts/check-wasm.sh: the check has to fail on a wasm that exports an EVM entry point.
(module
  (func (export "propose_evm")))
