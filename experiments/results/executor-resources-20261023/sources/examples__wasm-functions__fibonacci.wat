(module
  (memory (export "memory") 1)
  (func (export "invoke") (param $in i32) (param $len i32) (param $out i32) (param $cap i32) (result i32)
    (local $n i32) (local $a i32) (local $b i32) (local $tmp i32)
    local.get $in i32.load8_u local.set $n i32.const 1 local.set $b
    (block $done (loop $next
      local.get $n i32.eqz br_if $done
      local.get $a local.get $b i32.add local.set $tmp
      local.get $b local.set $a local.get $tmp local.set $b
      local.get $n i32.const 1 i32.sub local.set $n br $next))
    local.get $out local.get $a i32.store i32.const 4))
