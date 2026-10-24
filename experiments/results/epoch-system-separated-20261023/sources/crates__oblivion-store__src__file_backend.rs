use crate::{Backend, Config, Error};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

/// Bounded fixed bucket file. This contains ciphertext only: opening it does
/// not restore a controller. Use PathOram::restore with a trusted checkpoint.
pub struct FileBackend {
    file: File,
    bucket_count: usize,
    bucket_bytes: usize,
}
impl FileBackend {
    pub fn create(path: impl AsRef<Path>, config: &Config) -> Result<Self, Error> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(io_error)?;
        file.set_len(config.storage_bytes() as u64)
            .map_err(io_error)?;
        Ok(Self {
            file,
            bucket_count: config.bucket_count(),
            bucket_bytes: config.bucket_bytes(),
        })
    }
    pub fn open(path: impl AsRef<Path>, config: &Config) -> Result<Self, Error> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(io_error)?;
        if file.metadata().map_err(io_error)?.len() != config.storage_bytes() as u64 {
            return Err(Error::Integrity);
        }
        Ok(Self {
            file,
            bucket_count: config.bucket_count(),
            bucket_bytes: config.bucket_bytes(),
        })
    }
    pub fn sync_all(&mut self) -> Result<(), Error> {
        self.file.sync_all().map_err(io_error)
    }
    fn offset(&self, bucket: usize) -> Result<u64, Error> {
        if bucket >= self.bucket_count {
            return Err(Error::Address);
        }
        Ok((bucket * self.bucket_bytes) as u64)
    }
}
impl Backend for FileBackend {
    fn read_bucket(&mut self, bucket: usize) -> Result<Vec<u8>, Error> {
        self.file
            .seek(SeekFrom::Start(self.offset(bucket)?))
            .map_err(io_error)?;
        let mut bytes = vec![0; self.bucket_bytes];
        self.file.read_exact(&mut bytes).map_err(io_error)?;
        Ok(bytes)
    }
    fn write_bucket(&mut self, bucket: usize, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() != self.bucket_bytes {
            return Err(Error::BlockSize);
        }
        self.file
            .seek(SeekFrom::Start(self.offset(bucket)?))
            .map_err(io_error)?;
        self.file.write_all(bytes).map_err(io_error)
    }
}
pub(crate) fn io_error(error: std::io::Error) -> Error {
    Error::Backend(error.to_string())
}
