(module
  (memory (export "memory") 1)
  (func (export "invoke") (param $in i32) (param $len i32) (param $out i32) (param $cap i32) (result i32)
    local.get $out local.get $in local.get $len memory.copy
    local.get $len))
