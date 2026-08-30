(component
  ;; Native Wasmtime Component Model capsule.
  ;; The default Node runner consumes capsules/research-agent.wasm.b64 instead.
  (core module $m
    (memory (export "memory") 1)
    (global $heap (mut i32) (i32.const 4096))
    (data (i32.const 64) "{\"outcome\":\"tool\",\"request\":{\"name\":\"catalog.search\",\"arguments_json\":\"{\\\"query\\\":\\\"from native component checkpoint\\\",\\\"limit\\\":2}\"}}")
    (data (i32.const 512) "{\"outcome\":\"completed\",\"content_json\":\"{\\\"summary\\\":\\\"Native Wasmtime component resumed from checkpoint\\\",\\\"evidence\\\":[\\\"native-checkpoint-observed\\\"]}\"}")
    (func (export "realloc") (param $old i32) (param $old-size i32) (param $align i32) (param $new-size i32) (result i32)
      (local $ptr i32)
      global.get $heap
      local.set $ptr
      global.get $heap
      local.get $new-size
      i32.add
      global.set $heap
      local.get $ptr)
    (func (export "resume") (param $context-ptr i32) (param $context-len i32) (param $checkpoint-ptr i32) (param $checkpoint-len i32) (result i32)
      i32.const 16
      local.get $checkpoint-len
      i32.const 120
      i32.lt_u
      if (result i32)
        i32.const 64
      else
        i32.const 512
      end
      i32.store
      i32.const 20
      local.get $checkpoint-len
      i32.const 120
      i32.lt_u
      if (result i32)
        i32.const 134
      else
        i32.const 154
      end
      i32.store
      i32.const 16))
  (core instance $i (instantiate $m))
  (func $resume (param "context-json" string) (param "checkpoint-json" string) (result string)
    (canon lift
      (core func $i "resume")
      string-encoding=utf8
      (memory (core memory $i "memory"))
      (realloc (core func $i "realloc"))))
  (export "resume" (func $resume)))
