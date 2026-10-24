(module
  (memory (export "memory") 1)
  (func (export "invoke") (param $in i32) (param $len i32) (param $out i32) (param $cap i32) (result i32)
    (local $i i32) (local $sum i32)
    (block $done (loop $next
      local.get $i local.get $len i32.ge_u br_if $done
      local.get $sum local.get $in local.get $i i32.add i32.load8_u i32.add local.set $sum
      local.get $i i32.const 1 i32.add local.set $i br $next))
    local.get $out local.get $sum i32.store
    i32.const 4))
