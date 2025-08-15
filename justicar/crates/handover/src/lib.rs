//! A light weight library helping to do local attestation
//!
//! # Usage
//! ```ignore
//! fn main() {
//!     use sgx_api_lite as sgx;
//!     // In Enclave A
//!     let my_target_info = sgx::target_info().unwrap();
//!     let target_info_bytes = sgx::encode(&my_target_info);
//!
//!     // In Enclave B
//!     let its_target_info = unsafe { sgx::decode(target_info_bytes).unwrap() };
//!     let report = sgx::report(&its_target_info, &[0; 64]).unwrap();
//!     let report_bytes = sgx::encode(&report);
//!
//!     // In Enclave A
//!     let recv_report = unsafe { sgx::decode(report_bytes).unwrap() };
//!     let rv = sgx::verify(recv_report);
//!     assert!(rv.is_ok());
//! }
//! ```

use std::mem::{size_of, zeroed};

use anyhow::Result;
use anyhow::{anyhow, bail};
pub use sys::sgx_report_data_t as ReportData;
pub use sys::sgx_report_t as Report;
pub use sys::sgx_target_info_t as TargetInfo;
use thiserror::Error;

pub mod handover;
mod sys;
pub mod utils;

#[repr(C, align(512))]
struct SgxAligned<T>(T);

pub type HandoverResult<T> = std::result::Result<T, SgxError>;

#[derive(Debug, Error)]
pub enum SgxError {
    #[error("Operation failed due to internal error,because :{0}")]
    InternalError(String),

    #[error("Crypto error :{0}")]
    CryptoError(String),

    #[error("Serde fail because: {0}")]
    SerdeError(#[from] serde_json::Error),

    #[error("Parse fail because: {0}")]
    ParseError(#[from] std::string::FromUtf8Error),

    #[error("Handover fail :{0}")]
    HandoverFailed(#[from] anyhow::Error),
}

/// Serialize an SGX struct into a slice of bytes.
pub fn encode<T>(info: &T) -> &[u8] {
    let len = size_of::<T>();
    unsafe { std::slice::from_raw_parts(info as *const T as *const u8, len) }
}

/// Recover an SGX struct from slice of bytes. Supported types are: `Report`, `TargetInfo`.
///
/// # Safety
/// This function just casts the slice of bytes to an SGX struct. So using it with other types
/// is Undefined Behavior.
pub unsafe fn decode<T>(data: &[u8]) -> Result<&T> {
    if data.len() != size_of::<T>() {
        return Err(anyhow!(
            "fail decode ,because lenth error {} != {}",
            data.len(),
            size_of::<T>()
        ));
    }
    Ok(&*(data as *const _ as *const T))
}

/// Get the target info of the current enclave.
pub fn target_info() -> Result<TargetInfo> {
    unsafe {
        let targetinfo: SgxAligned<sys::sgx_target_info_t> = zeroed();
        let reportdata: SgxAligned<sys::sgx_report_data_t> = zeroed();
        let mut report: SgxAligned<sys::sgx_report_t> = zeroed();
        if sys::sgx_report(&targetinfo.0, &reportdata.0, &mut report.0) != 0 {
            bail!("Get local target info failed".to_string());
        }
        let body = report.0.body;
        let my_target_info = sys::_target_info_t {
            mr_enclave: body.mr_enclave,
            attributes: body.attributes,
            reserved1: zeroed(),
            config_svn: body.config_svn,
            misc_select: body.misc_select,
            reserved2: zeroed(),
            config_id: body.config_id,
            reserved3: zeroed(),
        };
        Ok(my_target_info)
    }
}

/// Create a report for the current enclave and could be verified by the enclave indecated
/// by `remote_target_info`.
pub fn report(remote_target_info: &TargetInfo, reportdata: &ReportData) -> Result<Report> {
    unsafe {
        let targetinfo = SgxAligned(*remote_target_info);
        let reportdata = SgxAligned(*reportdata);
        let mut report: SgxAligned<sys::sgx_report_t> = zeroed();
        if sys::sgx_report(&targetinfo.0, &reportdata.0, &mut report.0) != 0 {
            bail!("Get local attestation report failed")
        }
        Ok(report.0)
    }
}

/// Verify the report get from other enclave on the same machine.
pub fn verify(report: &Report) -> Result<()> {
    use cmac::{Cmac, Mac};

    let key = unsafe {
        let mut keyrequest: SgxAligned<sys::sgx_key_request_t> = zeroed();
        keyrequest.0.key_name = sys::SGX_REPORT_KEY;
        keyrequest.0.key_id = report.key_id;
        let mut key: SgxAligned<sys::sgx_key_128bit_t> = zeroed();

        if sys::sgx_getkey(&mut keyrequest.0, &mut key.0) != 0 {
            bail!("Verify report failed when get key")
        }
        key.0
    };

    let mut cmac = Cmac::<aes::Aes128>::new_from_slice(&key[..])
        .or(Err(anyhow!("Verify report failed when create cmac")).into())?;
    let body = encode(&report.body);
    cmac.update(body);

    let mac = cmac.finalize().into_bytes();
    if mac[..] == report.mac[..] {
        Ok(())
    } else {
        bail!("Verify failed, mac not match!")
    }
}
