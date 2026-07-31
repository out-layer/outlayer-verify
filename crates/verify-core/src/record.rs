//! The published attestation record, exactly as a coordinator serves it.
//!
//! Every field here is an *input* to verification, not a statement of fact. The whole point of the
//! three layers is that a record whose fields do not match what the TEE signed fails, so nothing in
//! this struct is trusted at the moment it is parsed.

use serde::{Deserialize, Serialize};

/// Attestations produced from this instant on commit to the extended (V1) field set.
///
/// The format must be decided by the record's timestamp and never by "whichever preimage happens to
/// match". A legacy quote commits to none of `caller_account_id`, `project_id`, `secrets_ref`,
/// `timestamp` or `attached_usd` — so if the verifier were allowed to fall back to the legacy shape
/// for a modern record, anyone could publish arbitrary values for those five fields and still be
/// told the signature covers them.
pub const V1_CUTOFF: i64 = 1_769_784_939; // 2026-01-30T14:55:39Z

/// Which set of fields the quote's `report_data` commits to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Format {
    /// Task type, id, code identity, payload hashes, block height.
    Legacy,
    /// The above plus caller, project, secrets reference, timestamp and attached payment.
    V1,
}

impl Format {
    pub fn for_timestamp(timestamp: i64) -> Self {
        if timestamp >= V1_CUTOFF {
            Format::V1
        } else {
            Format::Legacy
        }
    }

    /// Fields a record of this format does **not** prove. Printed rather than hidden: a proof that
    /// silently covers less than the reader assumes is worse than no proof.
    pub fn uncovered_fields(self) -> &'static [&'static str] {
        match self {
            Format::V1 => &[],
            Format::Legacy => &[
                "caller_account_id",
                "project_id",
                "secrets_ref",
                "timestamp",
                "attached_usd",
            ],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    pub task_id: i64,
    pub task_type: String,
    /// Base64 TDX quote.
    pub tdx_quote: String,
    /// RTMR3 as the coordinator read it. Never used as an expectation to compare the quote
    /// against — that comparison would be the quote against itself. Kept only to report a
    /// disagreement between what was stored and what the verified quote actually contains.
    #[serde(default)]
    pub worker_measurement: Option<String>,
    /// Unix seconds. Also the instant the quote is verified "as of".
    pub timestamp: i64,
    pub output_hash: String,

    #[serde(default)]
    pub input_hash: Option<String>,
    #[serde(default)]
    pub repo_url: Option<String>,
    #[serde(default)]
    pub commit_hash: Option<String>,
    #[serde(default)]
    pub build_target: Option<String>,
    #[serde(default)]
    pub wasm_hash: Option<String>,
    #[serde(default)]
    pub block_height: Option<u64>,
    #[serde(default)]
    pub caller_account_id: Option<String>,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub secrets_ref: Option<String>,
    #[serde(default)]
    pub attached_usd: Option<String>,

    /// Present for HTTPS calls.
    #[serde(default)]
    pub call_id: Option<String>,
    /// Present for on-chain calls.
    #[serde(default)]
    pub transaction_hash: Option<String>,
    #[serde(default)]
    pub request_id: Option<i64>,
}

impl Attestation {
    pub fn format(&self) -> Format {
        Format::for_timestamp(self.timestamp)
    }

    /// Decode the quote bytes. Rejects the development stubs explicitly rather than letting them
    /// fail later with a confusing parse error.
    pub fn quote_bytes(&self) -> Result<Vec<u8>, String> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let bytes = STANDARD
            .decode(self.tdx_quote.as_bytes())
            .map_err(|e| format!("quote is not valid base64: {e}"))?;

        // `tee_mode = "none"` stores base64("no-attestation-dev-mode"). It is not a broken quote,
        // it is the absence of one, and it must be named as such.
        if bytes == b"no-attestation-dev-mode" {
            return Err("this record carries no attestation: it was produced in development mode \
                        (tee_mode=none), which stores a placeholder instead of a TEE quote"
                .to_string());
        }
        if bytes.len() < 600 {
            return Err(format!(
                "quote is {} bytes, too short to be a TDX quote — not a genuine attestation",
                bytes.len()
            ));
        }
        Ok(bytes)
    }
}
