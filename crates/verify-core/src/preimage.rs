//! Rebuilding the commitment a TEE made to one execution.
//!
//! Before the quote is signed, the worker hashes the task's fields into `report_data`. Recomputing
//! that hash from the published record and finding it inside an Intel-signed quote is what turns
//! "here are some values" into "this input, this code and this output were what actually ran".
//!
//! The encoding is part of the attestation format, not an implementation detail: strings as UTF-8,
//! `task_id` and `timestamp` as little-endian i64, `block_height` as little-endian u64, and absent
//! optional fields contributing no bytes at all.
//!
//! That last rule is a known weakness and is documented rather than hidden: nothing is
//! length-prefixed, so `repo=None, commit="x"` hashes identically to `repo="x", commit=None`. It
//! takes a format change to fix, and until then a verifier author should know it exists.

use sha2::{Digest, Sha256};

use crate::record::{Attestation, Format};

/// The 32-byte commitment expected at `report_data[..32]`.
pub fn task_hash(att: &Attestation, format: Format) -> [u8; 32] {
    let mut h = Sha256::new();

    h.update(att.task_type.as_bytes());
    h.update(att.task_id.to_le_bytes());
    for field in [
        &att.repo_url,
        &att.commit_hash,
        &att.build_target,
        &att.wasm_hash,
        &att.input_hash,
    ] {
        if let Some(value) = field {
            h.update(value.as_bytes());
        }
    }
    h.update(att.output_hash.as_bytes());
    if let Some(height) = att.block_height {
        h.update(height.to_le_bytes());
    }

    if format == Format::V1 {
        for field in [&att.caller_account_id, &att.project_id, &att.secrets_ref] {
            if let Some(value) = field {
                h.update(value.as_bytes());
            }
        }
        h.update(att.timestamp.to_le_bytes());
        if let Some(usd) = &att.attached_usd {
            h.update(usd.as_bytes());
        }
    }

    h.finalize().into()
}

/// How the payload hashes in the record were produced, so a caller holding the original bytes can
/// reproduce them.
///
/// The two are **not** the same rule, and the difference is not cosmetic:
///
/// - `input_hash` is computed by the coordinator, whose build has serde_json's `preserve_order`
///   enabled, so the caller's key order survives into the hashed bytes.
/// - `output_hash` is computed by the worker, whose build does not, so its JSON map is a BTreeMap
///   and the keys come out sorted.
///
/// Both are compact (no spaces) and leave non-ASCII as UTF-8 rather than `\u`-escaping it.
/// Verified against live mainnet and testnet records, 2026-07-31.
pub mod payload {
    use super::*;

    /// SHA-256 of bytes that are already a string where they were recorded.
    ///
    /// On-chain executions carry their input and output as strings in the transaction itself, so
    /// there is nothing to canonicalise: re-parsing and re-serialising them could only introduce a
    /// difference that was never there.
    pub fn hash_raw(value: &str) -> String {
        hex::encode(Sha256::digest(value.as_bytes()))
    }

    /// SHA-256 of the request body as the coordinator serialised it: caller's key order preserved.
    pub fn input_hash(input: &serde_json::Value) -> String {
        hex::encode(Sha256::digest(compact(input, false).as_bytes()))
    }

    /// SHA-256 of the response as the worker serialised it: keys sorted.
    pub fn output_hash(output: &serde_json::Value) -> String {
        hex::encode(Sha256::digest(compact(output, true).as_bytes()))
    }

    fn compact(value: &serde_json::Value, sort_keys: bool) -> String {
        if !sort_keys {
            // serde_json::Value here preserves the order it was parsed in, matching the
            // coordinator's own serialisation.
            return value.to_string();
        }
        sorted(value).to_string()
    }

    fn sorted(value: &serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                let mut out = serde_json::Map::new();
                for key in keys {
                    out.insert(key.clone(), sorted(&map[key]));
                }
                serde_json::Value::Object(out)
            }
            serde_json::Value::Array(items) => {
                serde_json::Value::Array(items.iter().map(sorted).collect())
            }
            other => other.clone(),
        }
    }
}
