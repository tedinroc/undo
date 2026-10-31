;; Control for scripts/protocol-check.sh. It does nothing except import the host function that
;; near-sdk's high-level Promise type pulls in. On a node that lacks the function, every call
;; fails to link. It shows the pinned node can actually catch the problem the real contract
;; avoids. The signature is the one near-sys declares.
(module
  (import "env" "promise_batch_action_universal_state_init"
    (func $state_init (param i64 i64 i64 i64)))
  (memory (export "memory") 1)
  (func (export "ping"))
  (func (export "never_called")
    (call $state_init (i64.const 0) (i64.const 0) (i64.const 0) (i64.const 0))))
