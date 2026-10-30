use crate::Status;
use oblivion_store::{Backend, PathOram};
use std::{
    sync::{Arc, Mutex},
    time::Instant,
};
use wasmtime::{Caller, Linker, ResourceLimiter};

/// Host storage must bound its own wall-clock I/O. Epochs cannot interrupt a
/// blocking synchronous host call. Errors remain within the trusted boundary.
pub trait BlockStorage: Send {
    fn block_bytes(&self) -> usize;
    fn blocks(&self) -> usize;
    fn read(&mut self, address: usize) -> wasmtime::Result<Vec<u8>>;
    fn write(&mut self, address: usize, data: &[u8]) -> wasmtime::Result<()>;
}
impl<B: Backend + Send> BlockStorage for PathOram<B> {
    fn blocks(&self) -> usize {
        self.config().blocks()
    }
    fn block_bytes(&self) -> usize {
        self.config().block_bytes()
    }
    fn read(&mut self, address: usize) -> wasmtime::Result<Vec<u8>> {
        PathOram::read(self, address).map_err(wasmtime::Error::new)
    }
    fn write(&mut self, address: usize, data: &[u8]) -> wasmtime::Result<()> {
        PathOram::write(self, address, data).map_err(wasmtime::Error::new)
    }
}

pub(crate) struct Limits {
    pub memory_bytes: usize,
    pub denied: bool,
}
impl ResourceLimiter for Limits {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > self.memory_bytes || maximum.is_some_and(|max| desired > max) {
            self.denied = true;
            wasmtime::bail!("memory limit");
        }
        Ok(true)
    }
    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > 128 || maximum.is_some_and(|max| desired > max) {
            self.denied = true;
            wasmtime::bail!("table limit");
        }
        Ok(true)
    }
    fn instances(&self) -> usize {
        1
    }
    fn memories(&self) -> usize {
        1
    }
    fn tables(&self) -> usize {
        1
    }
}

pub(crate) struct Host {
    pub limits: Limits,
    pub storage: Arc<Mutex<dyn BlockStorage>>,
    pub accesses_left: usize,
    pub host_fuel: u64,
    pub deadline: Instant,
    pub failure: Option<Status>,
}
fn charge(caller: &mut Caller<'_, Host>) -> wasmtime::Result<()> {
    let state = caller.data_mut();
    if Instant::now() >= state.deadline {
        state.failure = Some(Status::Timeout);
        wasmtime::bail!("deadline");
    }
    if state.accesses_left == 0 {
        state.failure = Some(Status::Resource);
        wasmtime::bail!("host access budget");
    }
    state.accesses_left -= 1;
    let fuel = caller.get_fuel()?;
    let charge = caller.data().host_fuel;
    if fuel < charge {
        caller.data_mut().failure = Some(Status::OutOfFuel);
        wasmtime::bail!("host fuel");
    }
    caller.set_fuel(fuel - charge)?;
    Ok(())
}

pub(crate) fn link(linker: &mut Linker<Host>) -> wasmtime::Result<()> {
    linker.func_wrap(
        "oblivion",
        "read",
        |mut caller: Caller<'_, Host>, address: i32, ptr: i32| -> wasmtime::Result<()> {
            charge(&mut caller)?;
            if address < 0 || ptr < 0 {
                wasmtime::bail!("invalid guest pointer/address");
            }
            let memory = caller
                .get_export("memory")
                .and_then(|e| e.into_memory())
                .ok_or_else(|| wasmtime::Error::msg("missing memory"))?;
            let size = caller
                .data()
                .storage
                .lock()
                .map_err(|_| wasmtime::Error::msg("storage lock"))?
                .block_bytes();
            if size > caller.data().limits.memory_bytes
                || (ptr as usize)
                    .checked_add(size)
                    .is_none_or(|end| end > memory.data_size(&caller))
            {
                wasmtime::bail!("guest read buffer");
            }
            let result = caller
                .data()
                .storage
                .lock()
                .map_err(|_| wasmtime::Error::msg("storage lock"))?
                .read(address as usize);
            let bytes = match result {
                Ok(v) if v.len() == size => v,
                _ => {
                    caller.data_mut().failure = Some(Status::Storage);
                    wasmtime::bail!("storage failure");
                }
            };
            memory
                .write(&mut caller, ptr as usize, &bytes)
                .map_err(wasmtime::Error::new)?;
            Ok(())
        },
    )?;
    linker.func_wrap(
        "oblivion",
        "write",
        |mut caller: Caller<'_, Host>, address: i32, ptr: i32| -> wasmtime::Result<()> {
            charge(&mut caller)?;
            if address < 0 || ptr < 0 {
                wasmtime::bail!("invalid guest pointer/address");
            }
            let memory = caller
                .get_export("memory")
                .and_then(|e| e.into_memory())
                .ok_or_else(|| wasmtime::Error::msg("missing memory"))?;
            let size = caller
                .data()
                .storage
                .lock()
                .map_err(|_| wasmtime::Error::msg("storage lock"))?
                .block_bytes();
            if size > caller.data().limits.memory_bytes
                || (ptr as usize)
                    .checked_add(size)
                    .is_none_or(|end| end > memory.data_size(&caller))
            {
                wasmtime::bail!("guest write buffer");
            }
            let mut bytes = vec![0; size];
            memory
                .read(&caller, ptr as usize, &mut bytes)
                .map_err(wasmtime::Error::new)?;
            if caller
                .data()
                .storage
                .lock()
                .map_err(|_| wasmtime::Error::msg("storage lock"))?
                .write(address as usize, &bytes)
                .is_err()
            {
                caller.data_mut().failure = Some(Status::Storage);
                wasmtime::bail!("storage failure");
            }
            Ok(())
        },
    )?;
    Ok(())
}
