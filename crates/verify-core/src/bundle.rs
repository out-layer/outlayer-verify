//! The evidence bundle: one self-contained file that can be re-verified years later, offline.
//!
//! This is the artifact an auditor keeps. It holds the published record, the Intel-signed
//! collateral that was used, the payloads if the caller had them, and the answer the chain gave —
//! so re-checking it needs neither the network nor us to still exist.
//!
//! It also closes the collateral trap: superseded Intel collateral is served by nobody, so an
//! execution whose window has passed and was never captured can become impossible to verify. Once a
//! bundle is written, the collateral that covers it is inside the file.

use serde::{Deserialize, Serialize};

use crate::{record::Attestation, CollateralInfo, Evidence, Verification};

/// Bumped when the meaning of a field changes, so an old bundle is never read under new rules.
pub const BUNDLE_FORMAT: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    pub bundle_format: u32,
    /// How to check this file without trusting whoever handed it to you.
    pub how_to_verify: String,
    pub network: String,
    pub attestation: Attestation,
    /// The Intel-signed collateral used, verbatim. Altering it fails the signature chain, so
    /// carrying it here grants the bundle's author no influence over the verdict.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collateral: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collateral_info: Option<CollateralInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub register_contract: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub measurements_approved: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<serde_json::Value>,
    /// The verdict at the time of writing. Informational only — `outlayer-verify bundle` recomputes
    /// it from the evidence above rather than believing this field.
    pub verification: Verification,
}

impl Bundle {
    pub fn new(
        network: &str,
        attestation: Attestation,
        evidence: &Evidence,
        verification: Verification,
    ) -> Self {
        Bundle {
            bundle_format: BUNDLE_FORMAT,
            how_to_verify: "outlayer-verify bundle <this file> --offline".to_string(),
            network: network.to_string(),
            attestation,
            collateral: evidence.collateral.clone(),
            collateral_info: evidence.collateral_info.clone(),
            register_contract: evidence.register_contract.clone(),
            measurements_approved: evidence.measurements_approved,
            input: evidence.input.clone(),
            output: evidence.output.clone(),
            verification,
        }
    }

    /// Rebuild the evidence so the verdict can be recomputed instead of read.
    pub fn evidence(&self) -> Evidence {
        Evidence {
            collateral: self.collateral.clone(),
            collateral_info: self.collateral_info.clone(),
            measurements_approved: self.measurements_approved,
            register_contract: self.register_contract.clone(),
            input: self.input.clone(),
            output: self.output.clone(),
        }
    }
}
