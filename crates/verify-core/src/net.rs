//! Everything that touches the network, kept in one place so the verification itself stays pure.
//!
//! Three destinations, and only one of them is ours:
//!
//! - the coordinator, for the published record and the archived Intel collateral;
//! - public NEAR RPC, for the approved-measurement list;
//! - nothing else. Intel's root certificate is compiled into `dcap-qvl`, so the signature chain is
//!   checked against a key this tool carries, not one it is handed.
//!
//! Serving collateral from the coordinator gives us no influence over the verdict — the body is
//! Intel-signed and fails the chain if altered — and it spares the verifier a paid archival read.
//! `--collateral` lets anyone supply their own copy instead.

use std::time::Duration;

use crate::{record::Attestation, CollateralInfo};

const TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
}

impl Network {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value {
            "mainnet" => Ok(Network::Mainnet),
            "testnet" => Ok(Network::Testnet),
            other => Err(format!("unknown network {other:?}, expected mainnet or testnet")),
        }
    }

    pub fn api(self) -> &'static str {
        match self {
            Network::Mainnet => "https://api.outlayer.fastnear.com",
            Network::Testnet => "https://testnet-api.outlayer.fastnear.com",
        }
    }

    /// fastnear, never near.org.
    pub fn rpc(self) -> &'static str {
        match self {
            Network::Mainnet => "https://rpc.mainnet.fastnear.com",
            Network::Testnet => "https://rpc.testnet.fastnear.com",
        }
    }

    /// Archival, because ordinary nodes forget transactions after a couple of epochs and this tool
    /// exists to check old ones.
    pub fn archival_rpc(self) -> &'static str {
        match self {
            Network::Mainnet => "https://archival-rpc.mainnet.fastnear.com",
            Network::Testnet => "https://archival-rpc.testnet.fastnear.com",
        }
    }

    /// The contract executions are requested through.
    pub fn outlayer_contract(self) -> &'static str {
        match self {
            Network::Mainnet => "outlayer.near",
            Network::Testnet => "outlayer.testnet",
        }
    }

    /// The contract holding the approved worker measurements for this network.
    pub fn register_contract(self) -> &'static str {
        match self {
            Network::Mainnet => "worker.outlayer.near",
            Network::Testnet => "worker.outlayer.testnet",
        }
    }
}

fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_read(TIMEOUT)
        .timeout_connect(TIMEOUT)
        .build()
}

fn get_json(url: &str) -> Result<serde_json::Value, String> {
    match agent().get(url).call() {
        Ok(response) => response
            .into_json()
            .map_err(|e| format!("{url}: response was not JSON: {e}")),
        Err(ureq::Error::Status(404, _)) => Err(format!("{url}: not found (HTTP 404)")),
        Err(ureq::Error::Status(code, response)) => {
            let body = response.into_string().unwrap_or_default();
            Err(format!("{url}: HTTP {code} {}", body.chars().take(200).collect::<String>()))
        }
        Err(e) => Err(format!("{url}: {e}")),
    }
}

/// How the caller identifies the execution they want to check.
pub enum Lookup<'a> {
    /// A NEAR transaction hash — what someone who called the contract has.
    Transaction(&'a str),
    /// An HTTPS `call_id` — what `POST /call/...` returns.
    Call(&'a str),
    /// The internal task id, as dashboard links carry.
    Task(i64),
}

pub fn fetch_attestation(network: Network, lookup: Lookup<'_>) -> Result<Attestation, String> {
    let url = match lookup {
        Lookup::Transaction(tx) => format!("{}/attestations/by-tx/{tx}", network.api()),
        Lookup::Call(call) => format!("{}/attestations/by-call/{call}", network.api()),
        Lookup::Task(id) => format!("{}/attestations/{id}", network.api()),
    };
    let value = get_json(&url)?;
    serde_json::from_value(value).map_err(|e| format!("attestation record could not be parsed: {e}"))
}

/// Poll for an attestation that may not exist yet.
///
/// A completed call can legitimately answer 404 for a few seconds: the worker uploads the quote as
/// a separate step after the result is returned (observed on both networks). Giving up on the first
/// 404 would report a perfectly good execution as unattested.
pub fn await_attestation(
    network: Network,
    lookup: Lookup<'_>,
    attempts: u32,
    gap: Duration,
) -> Result<Attestation, String> {
    let mut last = String::new();
    for attempt in 0..attempts.max(1) {
        match fetch_attestation(
            network,
            match lookup {
                Lookup::Transaction(tx) => Lookup::Transaction(tx),
                Lookup::Call(call) => Lookup::Call(call),
                Lookup::Task(id) => Lookup::Task(id),
            },
        ) {
            Ok(att) => return Ok(att),
            Err(e) => {
                last = e;
                if attempt + 1 < attempts {
                    std::thread::sleep(gap);
                }
            }
        }
    }
    Err(last)
}

/// The Intel collateral that was valid when this execution ran.
pub fn fetch_collateral(
    network: Network,
    fmspc: &str,
    at_unix_seconds: i64,
) -> Result<(String, CollateralInfo), String> {
    let url = format!(
        "{}/public/collateral?fmspc={fmspc}&at={at_unix_seconds}",
        network.api()
    );
    let value = get_json(&url)?;
    let body = value
        .get("collateral")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "collateral response carries no `collateral` field".to_string())?
        .to_string();

    let info = CollateralInfo {
        fmspc: string_at(&value, "fmspc"),
        valid_from: string_at(&value, "valid_from"),
        valid_until: string_at(&value, "valid_until"),
        covers_execution_time: value
            .get("covers_requested_time")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        contract_id: string_at(&value, "contract_id"),
        collateral_sha256: string_at(&value, "collateral_sha256"),
        tx_hash: value.get("tx_hash").and_then(|v| v.as_str()).map(String::from),
        block_height: value.get("block_height").and_then(|v| v.as_u64()),
        source: string_at(&value, "source"),
    };
    Ok((body, info))
}

fn string_at(value: &serde_json::Value, key: &str) -> String {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

/// Ask the register contract whether these measurements are an approved worker build.
pub fn measurements_approved(
    network: Network,
    measurements: &crate::Measurements,
) -> Result<bool, String> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let args = serde_json::json!({ "measurements": measurements });
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "outlayer-verify",
        "method": "query",
        "params": {
            "request_type": "call_function",
            "finality": "final",
            "account_id": network.register_contract(),
            "method_name": "is_measurements_approved",
            "args_base64": STANDARD.encode(args.to_string()),
        }
    });

    let response: serde_json::Value = agent()
        .post(network.rpc())
        .send_json(request)
        .map_err(|e| format!("NEAR RPC: {e}"))?
        .into_json()
        .map_err(|e| format!("NEAR RPC: response was not JSON: {e}"))?;

    if let Some(error) = response.get("error") {
        return Err(format!("NEAR RPC error: {}", truncate(&error.to_string())));
    }
    let result = response
        .get("result")
        .ok_or_else(|| "NEAR RPC returned no result".to_string())?;
    if let Some(error) = result.get("error") {
        return Err(format!("contract call failed: {}", truncate(&error.to_string())));
    }

    let bytes: Vec<u8> = result
        .get("result")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "NEAR RPC result carries no return value".to_string())?
        .iter()
        .filter_map(|v| v.as_u64().map(|n| n as u8))
        .collect();

    let text = String::from_utf8(bytes)
        .map_err(|_| "contract returned non-UTF-8 data".to_string())?;
    serde_json::from_str::<bool>(&text)
        .map_err(|_| format!("contract returned {text:?}, expected true or false"))
}

fn truncate(text: &str) -> String {
    text.chars().take(200).collect()
}

/// Perform an HTTPS call and hand back the call id together with the exact payloads.
///
/// The payloads are the reason this lives here. For an on-chain call the input and output can be
/// recovered from archival RPC forever; for an HTTPS call only their hashes are ever stored, so a
/// caller who does not keep the request and the response can never verify that execution again.
/// Running the call through this wrapper is what makes the proof possible at all.
pub struct CallOutcome {
    pub call_id: String,
    pub status: String,
    pub attestation_url: Option<String>,
    pub input: serde_json::Value,
    pub output: Option<serde_json::Value>,
    pub error: Option<String>,
}

pub fn call_project(
    network: Network,
    project: &str,
    payment_key: &str,
    input: serde_json::Value,
) -> Result<CallOutcome, String> {
    let url = format!("{}/call/{project}", network.api());
    let body = serde_json::json!({ "input": input, "async": false });

    let response: serde_json::Value = match agent()
        .post(&url)
        .set("X-Payment-Key", payment_key)
        .send_json(body)
    {
        Ok(r) => r.into_json().map_err(|e| format!("call response was not JSON: {e}"))?,
        Err(ureq::Error::Status(code, response)) => {
            let text = response.into_string().unwrap_or_default();
            return Err(format!("call failed: HTTP {code} {}", truncate(&text)));
        }
        Err(e) => return Err(format!("call failed: {e}")),
    };

    Ok(CallOutcome {
        call_id: string_at(&response, "call_id"),
        status: string_at(&response, "status"),
        attestation_url: response
            .get("attestation_url")
            .and_then(|v| v.as_str())
            .map(String::from),
        input,
        output: response.get("output").cloned(),
        error: response.get("error").and_then(|v| v.as_str()).map(String::from),
    })
}

/// Recover an on-chain execution's input and output from the transaction itself.
///
/// This is what makes a blockchain proof complete without the caller keeping anything: the request
/// and the response are both in the transaction, permanently, so there is nothing to supply by hand.
/// (An HTTPS call has no such record — hence `run` and `--input/--output`.)
///
/// Read from an archival node: ordinary RPC nodes drop transactions older than a couple of epochs,
/// and the whole point here is checking executions from months ago.
pub fn fetch_chain_payloads(
    network: Network,
    tx_hash: &str,
    sender_account_id: &str,
) -> Result<(Option<String>, Option<String>), String> {
    use base64::{engine::general_purpose::STANDARD, Engine};

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": "outlayer-verify",
        "method": "EXPERIMENTAL_tx_status",
        "params": [tx_hash, sender_account_id],
    });

    let response: serde_json::Value = agent()
        .post(network.archival_rpc())
        .send_json(request)
        .map_err(|e| format!("archival RPC: {e}"))?
        .into_json()
        .map_err(|e| format!("archival RPC: response was not JSON: {e}"))?;

    if let Some(error) = response.get("error") {
        return Err(format!("archival RPC error: {}", truncate(&error.to_string())));
    }
    let receipts = response
        .pointer("/result/receipts_outcome")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "transaction has no receipts".to_string())?;

    // The input is announced by the contract as an `execution_requested` event, which carries the
    // request exactly as the contract stored it — the same string the worker later hashed.
    let mut input = None;
    for receipt in receipts {
        let logs = match receipt.pointer("/outcome/logs").and_then(|v| v.as_array()) {
            Some(logs) => logs,
            None => continue,
        };
        for log in logs.iter().filter_map(|l| l.as_str()) {
            let payload = match log.strip_prefix("EVENT_JSON:") {
                Some(rest) => rest,
                None => continue,
            };
            let event: serde_json::Value = match serde_json::from_str(payload) {
                Ok(value) => value,
                Err(_) => continue,
            };
            if event.get("event").and_then(|e| e.as_str()) != Some("execution_requested") {
                continue;
            }
            if let Some(data) = event.pointer("/data/0/request_data").and_then(|v| v.as_str()) {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(data) {
                    input = parsed
                        .get("input_data")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                }
            }
        }
    }

    // The output is the value the OutLayer contract returned, base64 in the receipt status.
    let mut output = None;
    for receipt in receipts {
        let executor = receipt.pointer("/outcome/executor_id").and_then(|v| v.as_str());
        if executor != Some(network.outlayer_contract()) {
            continue;
        }
        if let Some(encoded) = receipt
            .pointer("/outcome/status/SuccessValue")
            .and_then(|v| v.as_str())
        {
            if let Ok(bytes) = STANDARD.decode(encoded) {
                if let Ok(text) = String::from_utf8(bytes) {
                    output = Some(text);
                }
            }
        }
    }

    Ok((input, output))
}
