//! Verification of an OutLayer execution proof.
//!
//! Three independent layers, each answering a different question:
//!
//! 1. **Authenticity** — is this a genuine Intel TDX quote? Checked against the Intel root
//!    certificate embedded in `dcap-qvl`, using Intel-signed collateral. Without this layer the
//!    other two are just numbers somebody wrote down.
//! 2. **Identity** — do the measurements decoded from the *verified* quote appear in the on-chain
//!    list of approved builds? Read straight from the register contract over public NEAR RPC.
//! 3. **Binding** — does the quote commit to *this* execution? The TEE hashes the task's fields
//!    into `report_data` before signing, so recomputing that hash and matching it proves the
//!    signature covers this exact input, output and code.
//!
//! Nothing in this crate trusts the coordinator. The record, the collateral and the approved list
//! are inputs, and a wrong one fails a layer rather than being taken at face value.

pub mod bundle;
pub mod preimage;
pub mod quote;
pub mod record;

#[cfg(feature = "net")]
pub mod net;

use serde::{Deserialize, Serialize};

pub use quote::{Measurements, Verified};
pub use record::{Attestation, Format, V1_CUTOFF};

/// The outcome of one layer.
///
/// Three states, not two. A missing piece of evidence is not a failure — reporting it as one cries
/// wolf, and reporting it as a pass is a lie. `Unproven` says exactly which question could not be
/// answered and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "verdict", rename_all = "lowercase")]
pub enum Layer {
    Pass { detail: String },
    Fail { reason: String },
    Unproven { reason: String },
}

impl Layer {
    pub fn pass(detail: impl Into<String>) -> Self {
        Layer::Pass { detail: detail.into() }
    }
    pub fn fail(reason: impl Into<String>) -> Self {
        Layer::Fail { reason: reason.into() }
    }
    pub fn unproven(reason: impl Into<String>) -> Self {
        Layer::Unproven { reason: reason.into() }
    }
    pub fn is_pass(&self) -> bool {
        matches!(self, Layer::Pass { .. })
    }
    pub fn is_fail(&self) -> bool {
        matches!(self, Layer::Fail { .. })
    }
    pub fn label(&self) -> &'static str {
        match self {
            Layer::Pass { .. } => "PASS",
            Layer::Fail { .. } => "FAIL",
            Layer::Unproven { .. } => "UNPROVEN",
        }
    }
}

/// Where a piece of collateral came from, carried through to the output so a reader can go and
/// check it independently.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollateralInfo {
    pub fmspc: String,
    pub valid_from: String,
    pub valid_until: String,
    /// False when no published collateral covers the execution's own timestamp.
    pub covers_execution_time: bool,
    pub contract_id: String,
    pub collateral_sha256: String,
    #[serde(default)]
    pub tx_hash: Option<String>,
    #[serde(default)]
    pub block_height: Option<u64>,
    pub source: String,
}

/// Everything the verification needs that does not come from the record itself.
#[derive(Debug, Clone, Default)]
pub struct Evidence {
    /// Intel-signed collateral for the quote's platform, valid at the execution's timestamp.
    pub collateral: Option<String>,
    pub collateral_info: Option<CollateralInfo>,
    /// Answer from `is_measurements_approved`, and the contract that was asked.
    pub measurements_approved: Option<bool>,
    pub register_contract: Option<String>,
    /// The request body as sent, for HTTPS callers who kept it. Hashed the way the coordinator
    /// serialises it.
    pub input: Option<serde_json::Value>,
    /// The response as received.
    pub output: Option<serde_json::Value>,
    /// Payloads recovered from the chain for an on-chain execution. These are hashed exactly as
    /// they appear on chain — they are already strings there, so no re-serialisation is involved
    /// and none may be applied.
    pub input_raw: Option<String>,
    pub output_raw: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verification {
    pub task_id: i64,
    pub task_type: String,
    pub timestamp: i64,
    pub format: Format,
    pub authenticity: Layer,
    pub identity: Layer,
    pub binding: Layer,
    /// Present only when the caller supplied the payloads.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<Layer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<Layer>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcb_status: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advisory_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measurements: Option<Measurements>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collateral: Option<CollateralInfo>,
    /// Fields this record's format does not commit to. Empty for V1.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uncovered_fields: Vec<String>,

    // Everything below is the working of the proof rather than its conclusion. A verdict a reader
    // cannot take apart is just a different way of saying "trust me", so the values that were
    // compared are reported alongside the comparison.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quote_size: Option<usize>,
    /// The commitment found inside the signed quote.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_data_prefix: Option<String>,
    /// Must be all zeros in this format.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report_data_suffix: Option<String>,
    /// What the published fields hash to. Equal to `report_data_prefix` when the binding holds.
    pub expected_task_hash: String,
    /// Hash of the request the caller supplied, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_hash_computed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_hash_computed: Option<String>,
}

impl Verification {
    /// Proven only when every layer that ran passed and none was left unproven.
    pub fn is_proven(&self) -> bool {
        let core = [&self.authenticity, &self.identity, &self.binding];
        let payloads = [self.input.as_ref(), self.output.as_ref()];
        core.iter().all(|l| l.is_pass())
            && payloads.into_iter().flatten().all(|l| l.is_pass())
    }

    pub fn has_failure(&self) -> bool {
        let core = [&self.authenticity, &self.identity, &self.binding];
        let payloads = [self.input.as_ref(), self.output.as_ref()];
        core.iter().any(|l| l.is_fail())
            || payloads.into_iter().flatten().any(|l| l.is_fail())
    }
}

/// Run every layer that the supplied evidence allows. Pure: no I/O, no clock.
///
/// A layer that cannot run does not abort the rest — the caller is told exactly how far
/// verification got, which is more useful than a single red cross and cannot be mistaken for a
/// clean pass.
pub fn verify(att: &Attestation, evidence: &Evidence) -> Verification {
    let format = att.format();
    let mut out = Verification {
        task_id: att.task_id,
        task_type: att.task_type.clone(),
        timestamp: att.timestamp,
        format,
        authenticity: Layer::unproven("not attempted"),
        identity: Layer::unproven("not attempted"),
        binding: Layer::unproven("not attempted"),
        input: None,
        output: None,
        tcb_status: None,
        advisory_ids: Vec::new(),
        measurements: None,
        collateral: evidence.collateral_info.clone(),
        uncovered_fields: format
            .uncovered_fields()
            .iter()
            .map(|s| s.to_string())
            .collect(),
        quote_size: None,
        report_data_prefix: None,
        report_data_suffix: None,
        expected_task_hash: hex::encode(preimage::task_hash(att, format)),
        input_hash_computed: None,
        output_hash_computed: None,
    };

    // --- Layer 1: authenticity -------------------------------------------------------------
    let quote_bytes = match att.quote_bytes() {
        Ok(bytes) => bytes,
        Err(reason) => {
            // A stub or a malformed blob is a failure, not a gap: the record claims to carry an
            // attestation and does not.
            out.authenticity = Layer::fail(reason);
            out.identity = Layer::unproven("no verified quote to take measurements from");
            out.binding = Layer::unproven("no verified quote to compare report_data against");
            return out;
        }
    };

    let collateral = match &evidence.collateral {
        Some(c) => c,
        None => {
            out.authenticity = Layer::unproven(
                "no Intel collateral available for this platform at the execution's timestamp",
            );
            out.identity = Layer::unproven("measurements are only trustworthy from a verified quote");
            out.binding = Layer::unproven("report_data is only trustworthy from a verified quote");
            return out;
        }
    };

    let verified = match quote::verify(&quote_bytes, collateral, att.timestamp as u64) {
        Ok(v) => v,
        Err(reason) => {
            out.authenticity = Layer::fail(reason);
            out.identity = Layer::unproven("measurements are only trustworthy from a verified quote");
            out.binding = Layer::unproven("report_data is only trustworthy from a verified quote");
            return out;
        }
    };

    out.tcb_status = Some(verified.tcb_status.clone());
    out.advisory_ids = verified.advisory_ids.clone();
    out.measurements = Some(verified.measurements.clone());
    out.quote_size = Some(quote_bytes.len());
    out.report_data_prefix = Some(verified.report_data_prefix.clone());
    out.report_data_suffix = Some(verified.report_data_suffix.clone());
    out.authenticity = if verified.tcb_is_current() {
        Layer::pass("Intel signature chain valid, TCB UpToDate")
    } else {
        // Genuine silicon, genuine signature — but Intel is flagging the platform. Neither a pass
        // nor a forgery.
        Layer::unproven(format!(
            "signature chain is valid, but Intel reports TCB status {}{}",
            verified.tcb_status,
            if verified.advisory_ids.is_empty() {
                String::new()
            } else {
                format!(" (advisories: {})", verified.advisory_ids.join(", "))
            }
        ))
    };

    // A quote whose collateral does not cover the execution's own moment was judged against a
    // neighbouring window. Say so: a revocation published inside the gap would not be visible.
    if let Some(info) = &evidence.collateral_info {
        if !info.covers_execution_time && out.authenticity.is_pass() {
            out.authenticity = Layer::unproven(format!(
                "no published collateral covers this execution's timestamp; verified against the \
                 nearest window ({} .. {}), so a revocation published inside the gap would not \
                 appear here",
                info.valid_from, info.valid_until
            ));
        }
    }

    // --- Layer 2: identity -----------------------------------------------------------------
    let contract = evidence.register_contract.as_deref().unwrap_or("<unknown>");
    out.identity = match evidence.measurements_approved {
        Some(true) => Layer::pass(format!("measurements approved on {contract}")),
        Some(false) => Layer::fail(format!(
            "measurements are NOT in the approved list on {contract} — the code that ran is not a \
             build this operator has published"
        )),
        None => Layer::unproven("the approved-measurement list could not be read from the chain"),
    };

    // --- Layer 3: binding ------------------------------------------------------------------
    let expected = out.expected_task_hash.clone();
    out.binding = if expected == verified.report_data_prefix {
        if verified.report_data_suffix.chars().all(|c| c == '0') {
            Layer::pass("report_data commits to exactly these task fields")
        } else {
            Layer::fail(format!(
                "task hash matches but report_data[32..] is {} rather than zero — this record was \
                 not produced by a known worker build",
                verified.report_data_suffix
            ))
        }
    } else {
        Layer::fail(format!(
            "report_data commits to {} but the published fields hash to {} — the record does not \
             describe the execution that was signed",
            verified.report_data_prefix, expected
        ))
    };

    // --- Payloads --------------------------------------------------------------------------
    if let Some(raw) = &evidence.input_raw {
        let computed = preimage::payload::hash_raw(raw);
        out.input_hash_computed = Some(computed.clone());
        out.input = Some(match &att.input_hash {
            Some(stored) if *stored == computed => Layer::pass("recovered from the transaction"),
            Some(stored) => Layer::fail(format!(
                "the input recorded on chain hashes to {computed}, the attested value is {stored}"
            )),
            None => Layer::unproven("this record carries no input_hash".to_string()),
        });
    } else if let Some(input) = &evidence.input {
        let computed = preimage::payload::input_hash(input);
        out.input_hash_computed = Some(computed.clone());
        out.input = Some(match &att.input_hash {
            Some(stored) if *stored == computed => Layer::pass("the request you supplied"),
            Some(stored) => Layer::fail(format!(
                "the supplied request hashes to {computed}, the attested value is {stored}"
            )),
            None => Layer::unproven("this record carries no input_hash".to_string()),
        });
    }
    if let Some(raw) = &evidence.output_raw {
        let computed = preimage::payload::hash_raw(raw);
        out.output_hash_computed = Some(computed.clone());
        out.output = Some(if att.output_hash == computed {
            Layer::pass("recovered from the transaction")
        } else {
            Layer::fail(format!(
                "the output recorded on chain hashes to {computed}, the attested value is {}",
                att.output_hash
            ))
        });
    } else if let Some(output) = &evidence.output {
        let computed = preimage::payload::output_hash(output);
        out.output_hash_computed = Some(computed.clone());
        out.output = Some(if att.output_hash == computed {
            Layer::pass("the response you supplied")
        } else {
            Layer::fail(format!(
                "the supplied response hashes to {computed}, the attested value is {}",
                att.output_hash
            ))
        });
    }

    out
}
