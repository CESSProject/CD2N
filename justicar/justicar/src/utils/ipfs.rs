use anyhow::{Context, Result};
use ipfs_cid::generate_cid_v0;

pub fn compute_ipfs_cid_from_bytes(data: Vec<u8>) -> Result<String> {
    let bytes_slice = data.as_slice();

    let cid_hash = generate_cid_v0(bytes_slice).context("generate CID v0 failed")?;
    Ok(cid_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;

    #[test]
    fn test_compute_ipfs_cid_from_bytes() -> Result<()> {
        let mut file = File::open("./example.txt")?;
        let mut file_content = Vec::new();
        file.read_to_end(&mut file_content)?;

        let cid = compute_ipfs_cid_from_bytes(file_content)?;

        assert_eq!(
            "QmPSei9A8itoGh2Ng5pxqrmiz5uD1oHh9wLdcH7Q681ULY".to_string(),
            cid
        );

        Ok(())
    }
}
