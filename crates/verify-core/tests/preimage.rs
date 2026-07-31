//! The preimage is implemented three times across this project — here in Rust, in TypeScript in the
//! dashboard, and as a Python snippet the dashboard offers for copying. Three independent
//! implementations of an unprefixed concatenation is precisely how they drift apart, so these
//! vectors are real records pulled from production and each one pins the byte layout.
//!
//! They also pin the format boundary from both sides, which matters for a reason that is not
//! obvious: the legacy preimage commits to none of caller, project, secrets, timestamp or payment.
//! If the verifier were allowed to try both shapes and accept whichever matched, anyone could
//! republish an old record with invented values for those five fields and be told the signature
//! covers them. The format is chosen by timestamp, and these tests are what keep that honest.

use base64::{engine::general_purpose::STANDARD, Engine};
use outlayer_verify_core::{
    preimage::task_hash,
    record::{Attestation, Format},
};

fn load(name: &str) -> Attestation {
    let path = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).expect("fixture is missing");
    serde_json::from_str(&text).expect("fixture is not a valid attestation record")
}

/// The commitment as it appears inside the signed quote.
fn report_data_prefix(att: &Attestation) -> String {
    let quote = STANDARD.decode(att.tdx_quote.as_bytes()).unwrap();
    hex::encode(&quote[568..600])
}

#[test]
fn v1_record_matches_the_signed_commitment() {
    // Mainnet task 205123, 2026-07-29. HTTPS execution on a self-hosted node.
    let att = load("mainnet-205123-v1.json");
    assert_eq!(att.format(), Format::V1);
    assert_eq!(hex::encode(task_hash(&att, Format::V1)), report_data_prefix(&att));
}

#[test]
fn legacy_record_matches_the_signed_commitment() {
    // Mainnet task 500, 2026-01-30T14:01:56Z — 53 minutes before the V1 cut-off, which is what
    // makes it useful: it pins the boundary rather than some comfortably old record.
    let att = load("mainnet-500-legacy.json");
    assert_eq!(att.format(), Format::Legacy);
    assert_eq!(hex::encode(task_hash(&att, Format::Legacy)), report_data_prefix(&att));
}

#[test]
fn chain_record_matches_the_signed_commitment() {
    // Testnet task 2008: an on-chain call, so `block_height` and `caller_account_id` participate in
    // the hash. The HTTPS fixtures above cannot cover those bytes.
    let att = load("testnet-2008-chain.json");
    assert!(att.block_height.is_some(), "fixture should be a chain-backed record");
    assert_eq!(hex::encode(task_hash(&att, att.format())), report_data_prefix(&att));
}

#[test]
fn the_two_formats_are_never_interchangeable() {
    // If these ever coincided, choosing the format by timestamp would be pointless.
    for name in ["mainnet-205123-v1.json", "mainnet-500-legacy.json"] {
        let att = load(name);
        assert_ne!(
            task_hash(&att, Format::V1),
            task_hash(&att, Format::Legacy),
            "{name}: the two preimages must be distinguishable"
        );
    }
}

#[test]
fn a_legacy_record_does_not_claim_to_cover_v1_fields() {
    assert!(Format::V1.uncovered_fields().is_empty());
    assert!(Format::Legacy
        .uncovered_fields()
        .contains(&"attached_usd"));
}

#[test]
fn development_stubs_are_rejected_by_name() {
    let mut att = load("mainnet-205123-v1.json");
    att.tdx_quote = STANDARD.encode(b"no-attestation-dev-mode");
    let error = att.quote_bytes().unwrap_err();
    assert!(
        error.contains("development mode"),
        "a dev-mode placeholder must be named as such, got: {error}"
    );
}

#[test]
fn tampering_with_a_published_field_breaks_the_binding() {
    let att = load("mainnet-205123-v1.json");
    let signed = report_data_prefix(&att);

    let mut altered = att.clone();
    altered.output_hash = format!("0{}", &att.output_hash[1..]);
    assert_ne!(hex::encode(task_hash(&altered, Format::V1)), signed);

    let mut altered = att.clone();
    altered.caller_account_id = Some("attacker.near".to_string());
    assert_ne!(hex::encode(task_hash(&altered, Format::V1)), signed);
}

/// The trust anchor is the one thing in this crate that cannot be allowed to change quietly: swap
/// it and every verdict becomes meaningless while every test still passes. Pinned by hash, matching
/// Intel's published certificate at
/// https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.cer
#[test]
fn intel_root_ca_is_the_published_one() {
    assert_eq!(
        outlayer_verify_core::quote::intel_root_fingerprint(),
        "44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3"
    );
}
