//! The two things done with the quote itself: read the platform id out of it, and verify it.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Intel's SGX Provisioning Certification Root CA, in DER, shipped inside this binary.
///
/// Everything a quote proves ultimately rests on this one key, so it is committed here rather than
/// left implicit inside a dependency: a reader can hash the file, hash Intel's published copy, and
/// see that the two agree. Nothing is fetched at runtime — a verifier that downloads its own trust
/// anchor can be redirected, and then it verifies nothing.
///
/// Source: <https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.cer>
/// Subject: CN=Intel SGX Root CA, O=Intel Corporation, valid 2018-05-21 .. 2049-12-31.
pub const INTEL_ROOT_CA_DER: &[u8] =
    include_bytes!("Intel_SGX_Provisioning_Certification_RootCA.der");

/// SHA-256 of the root above, for printing next to a verdict so the trust anchor is checkable
/// rather than asserted.
pub fn intel_root_fingerprint() -> String {
    hex::encode(Sha256::digest(INTEL_ROOT_CA_DER))
}

/// What Intel's verifier actually checks, in the order the library performs it.
///
/// Reproduced from `dcap-qvl`'s own documentation of `verify_impl` rather than paraphrased, because
/// a list of checks that does not match the code is worse than no list.
pub const CHECKS_PERFORMED: [&str; 8] = [
    "TCB Info document signed by Intel",
    "QE Identity document signed by Intel",
    "PCK certificate chains to the Intel root",
    "QE report signed by that PCK certificate",
    "QE report hash covers the attestation key",
    "QE report satisfies the QE Identity policy",
    "enclave report signed by the attestation key",
    "platform TCB (CPU_SVN, PCE_SVN, FMSPC) matches TCB Info",
];

/// Measurements of the code that ran, decoded from a quote. Lowercase hex.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Measurements {
    pub mrtd: String,
    pub rtmr0: String,
    pub rtmr1: String,
    pub rtmr2: String,
    pub rtmr3: String,
}

fn measurements_of(report: &dcap_qvl::quote::Report) -> Option<Measurements> {
    let td = report.as_td10()?;
    Some(Measurements {
        mrtd: hex::encode(td.mr_td),
        rtmr0: hex::encode(td.rt_mr0),
        rtmr1: hex::encode(td.rt_mr1),
        rtmr2: hex::encode(td.rt_mr2),
        rtmr3: hex::encode(td.rt_mr3),
    })
}

/// What can be read from a quote *before* verifying it.
///
/// Used for exactly one purpose: learning which platform's collateral to fetch. Nothing here is
/// established fact — an attacker controls every byte of an unverified quote — so none of it may be
/// displayed as a result.
pub struct Unverified {
    /// Platform id, lowercase hex. Taken from the signed PCK certificate, never from a worker name:
    /// a name is mutable and forgeable, this is inside the material Intel signs.
    pub fmspc: String,
}

pub fn peek(quote: &[u8]) -> Result<Unverified, String> {
    let parsed = dcap_qvl::quote::Quote::parse(quote)
        .map_err(|e| format!("quote could not be decoded: {e:?}"))?;
    let fmspc = dcap_qvl::intel::quote_fmspc(&parsed)
        .map_err(|e| format!("quote carries no usable FMSPC: {e:?}"))?;
    Ok(Unverified {
        fmspc: hex::encode(fmspc).to_lowercase(),
    })
}

/// The result of a successful Intel verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verified {
    /// Intel's TCB status, verbatim. `Ok` from the verifier does **not** mean "up to date": the
    /// crate also succeeds for `OutOfDate` and `ConfigurationNeeded`, where the signature is
    /// genuine but Intel is flagging the platform. Only `Revoked` is an outright error. So this
    /// string is surfaced instead of being collapsed into a pass/fail bit.
    pub tcb_status: String,
    pub advisory_ids: Vec<String>,
    /// Taken from the verified quote, not from any surrounding metadata.
    pub measurements: Measurements,
    /// `report_data[..32]`, hex — the commitment to compare against the recomputed task hash.
    pub report_data_prefix: String,
    /// `report_data[32..]`, hex. The format leaves these zero; anything else means the record was
    /// produced by something other than the worker this tool knows about.
    pub report_data_suffix: String,
}

impl Verified {
    pub fn tcb_is_current(&self) -> bool {
        self.tcb_status == "UpToDate"
    }
}

/// Verify a quote against Intel-issued collateral, as of `now_secs`.
///
/// `now_secs` must be the moment the attestation was produced, not the wall clock. Collateral is
/// valid only inside its own window, and the crate enforces both ends of it, so judging a
/// three-month-old execution against today's collateral rejects a perfectly good quote. The
/// verifier chooses this parameter; the crate never compares it to the quote's own timestamp.
pub fn verify(quote: &[u8], collateral_json: &str, now_secs: u64) -> Result<Verified, String> {
    let collateral: dcap_qvl::QuoteCollateralV3 = serde_json::from_str(collateral_json)
        .map_err(|e| format!("collateral could not be parsed: {e}"))?;

    // Verified against the root committed in this repository, not the one the library happens to
    // embed, so the trust anchor is ours to show and yours to check.
    let report = dcap_qvl::verify::QuoteVerifier::new(INTEL_ROOT_CA_DER.to_vec())
        .verify_with::<dcap_qvl::configs::RustCryptoConfig>(quote, &collateral, now_secs)
        .map_err(|e| format!("{e:?}"))?;

    let measurements = measurements_of(&report.report)
        .ok_or_else(|| "verified quote is not a TDX 1.0 report".to_string())?;
    let td = report
        .report
        .as_td10()
        .ok_or_else(|| "verified quote is not a TDX 1.0 report".to_string())?;

    Ok(Verified {
        tcb_status: report.status.clone(),
        advisory_ids: report.advisory_ids.clone(),
        measurements,
        report_data_prefix: hex::encode(&td.report_data[..32]),
        report_data_suffix: hex::encode(&td.report_data[32..]),
    })
}
