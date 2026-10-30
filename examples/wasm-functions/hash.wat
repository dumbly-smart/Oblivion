;; FNV-like checksum workload, NOT a cryptographic hash primitive.
(module
  (memory (export "memory") 1)
  (func (export "invoke") (param $in i32) (param $len i32) (param $out i32) (param $cap i32) (result i32)
    (local $i i32) (local $h i32)
    i32.const 2166136261 local.set $h
    (block $done (loop $next
      local.get $i local.get $len i32.ge_u br_if $done
      local.get $h local.get $in local.get $i i32.add i32.load8_u i32.xor i32.const 16777619 i32.mul local.set $h
      local.get $i i32.const 1 i32.add local.set $i br $next))
    local.get $out local.get $h i32.store i32.const 4))
