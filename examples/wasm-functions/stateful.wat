(module
  (import "oblivion" "read" (func $read (param i32 i32)))
  (import "oblivion" "write" (func $write (param i32 i32)))
  (memory (export "memory") 1)
  (func (export "invoke") (param $in i32) (param $len i32) (param $out i32) (param $cap i32) (result i32)
    local.get $in i32.const 4 i32.add i32.load local.get $out call $read
    local.get $out local.get $out i32.load i32.const 1 i32.add i32.store
    local.get $in i32.const 4 i32.add i32.load local.get $out call $write
    i32.const 4))
