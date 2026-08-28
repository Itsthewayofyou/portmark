(module
  ;; WIT-shaped JSON-lowered decision ABI v1.
  ;; Exports resume(context-json, checkpoint-json) and returns a pointer/length
  ;; pair encoded as (pointer << 32) | length. The capsule declares no imports,
  ;; so it has no ambient filesystem, network, process, environment, clock,
  ;; randomness, or credential access.
  (memory (export "memory") 1)
  (data (i32.const 16) "{\"outcome\":\"completed\",\"content_json\":\"{\\\"summary\\\":\\\"Wasm completed through WIT resume\\\",\\\"evidence\\\":[]}\"}")
  (func (export "resume") (param $context_ptr i32) (param $context_len i32) (param $checkpoint_ptr i32) (param $checkpoint_len i32) (result i64)
    i64.const 68719476844))
