use anyhow::Result;
use serde::Serialize;

pub trait Sealing {
    fn seal_data<Sealable: ?Sized + Serialize>(&mut self, data: &Sealable) -> Result<()>;

    fn unseal_data<T: serde::de::DeserializeOwned>(&mut self) -> Result<T>;
}
