#![cfg_attr(all(not(test), not(feature = "std")), no_std)]

#[macro_use]
extern crate alloc;

pub mod dcap;
pub mod types;

#[cfg(feature = "report")]
pub mod gramine;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    InvalidCertificate,
    InvalidSignature,
    CodecError,

    // DCAP
    TCBInfoExpired,
    KeyLengthIsInvalid,
    PublicKeyIsInvalid,
    RsaSignatureIsInvalid,
    DerEncodingError,
    UnsupportedDCAPQuoteVersion,
    UnsupportedDCAPAttestationKeyType,
    UnsupportedQuoteAuthData,
    UnsupportedDCAPPckCertFormat,
    LeafCertificateParsingError,
    CertificateChainIsInvalid,
    CertificateChainIsTooShort,
    IntelExtensionCertificateDecodingError,
    IntelExtensionAmbiguity,
    CpuSvnLengthMismatch,
    CpuSvnDecodingError,
    PceSvnDecodingError,
    PceSvnLengthMismatch,
    FmspcLengthMismatch,
    FmspcDecodingError,
    FmspcMismatch,
    QEReportHashMismatch,
    IsvEnclaveReportSignatureIsInvalid,
    DerDecodingError,
    OidIsMissing,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_async_add() {
        let data = "Test Dcap".as_bytes();
        let pccs_url = "https://dcap-sgp-dev.cess.cloud/sgx/certification/v4/";
        let timeout = Duration::from_secs(10);
        let att_report =
            match dcap::report::create_attestation_report(data, pccs_url, timeout).await {
                Ok(r) => r,
                Err(e) => panic!("create report fail :{:?}", e.to_string()),
            };

        let (raw_quote, quote_collateral) = if let types::AttestationReport::SgxDcap {
            quote: raw_quote,
            collateral: c,
        } = att_report
        {
            let quote_collateral = match c.unwrap() {
                types::Collateral::SgxV30(quote_collateral) => quote_collateral,
            };
            (raw_quote, quote_collateral)
        } else {
            panic!("not dcap attestation")
        };

        let now = chrono::Utc::now().timestamp() as u64;
        let (report_data, tcb_hash, tcb_status, advisory_ids) =
            match dcap::verify(&raw_quote, &quote_collateral, now) {
                Ok(r) => (r.0, r.1, r.2, r.3),
                Err(e) => {
                    panic!("fail to verify report :{:?}", e)
                }
            };
        println!(
            "report data is :{:?}",
            String::from_utf8(report_data.to_vec())
        );
        println!("prime_data is :{:?}", hex::encode(tcb_hash));
        println!("tcb_status is :{:?}", tcb_status);
        println!("advisory_ids is :{:?}", advisory_ids);
    }
}
