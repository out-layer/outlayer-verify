//! `outlayer-verify` — check an OutLayer execution proof yourself.
//!
//! No account, no config file, no key material. Everything the tool needs is an argument, and the
//! Intel root certificate it checks signatures against is compiled in rather than fetched.

use std::process::ExitCode;

mod render;

use outlayer_verify_core as core;
use outlayer_verify_core::{bundle::Bundle, net, Evidence, Verification};
use render::Style;

const USAGE: &str = "\
outlayer-verify — verify an OutLayer execution proof

USAGE
  outlayer-verify tx <near-tx-hash>        prove an on-chain execution
  outlayer-verify call <call-id>           prove an HTTPS execution
  outlayer-verify job <task-id>            prove by internal task id (what dashboard links carry)
  outlayer-verify run <owner>/<project>    execute, capture the payloads, then prove
  outlayer-verify bundle <file.json>       re-check a saved bundle

OPTIONS
  --network <mainnet|testnet>   default: mainnet
  --input <file|json>           the request you sent (HTTPS executions), or the body for `run`
  --output <file|json>          the response you received (HTTPS executions)
  --payment-key <key>           OWNER:NONCE:KEY, for `run`; or $OUTLAYER_PAYMENT_KEY
  --secrets-ref <acct/profile>  secrets the program may read, for `run`
  --collateral <file>           use your own copy of the Intel collateral
  --bundle <file>               save a self-contained evidence bundle to this path
  --offline                     no network at all; only valid with `bundle`
  --short                       one line: the verdict only
  --json                        machine-readable result, with every value compared
  --no-color                    plain text (also honours NO_COLOR)
  -h, --help

EXIT CODES
  0  every layer passed
  1  a layer FAILED — the proof is invalid
  2  UNPROVEN — the check could not be completed
  3  usage error
";

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(3)
        }
    }
}

struct Args {
    command: String,
    value: String,
    network: net::Network,
    input: Option<serde_json::Value>,
    output: Option<serde_json::Value>,
    payment_key: Option<String>,
    secrets_ref: Option<serde_json::Value>,
    collateral: Option<String>,
    bundle_path: Option<String>,
    offline: bool,
    short: bool,
    json: bool,
    no_color: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut raw = std::env::args().skip(1).collect::<Vec<_>>();
    if raw.is_empty() || raw.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        std::process::exit(if raw.is_empty() { 3 } else { 0 });
    }

    let command = raw.remove(0);
    let mut value = String::new();
    if !raw.is_empty() && !raw[0].starts_with("--") {
        value = raw.remove(0);
    }

    let mut args = Args {
        command,
        value,
        network: net::Network::Mainnet,
        input: None,
        output: None,
        payment_key: std::env::var("OUTLAYER_PAYMENT_KEY").ok(),
        secrets_ref: None,
        collateral: None,
        bundle_path: None,
        offline: false,
        short: false,
        json: false,
        no_color: false,
    };

    let mut i = 0;
    while i < raw.len() {
        let flag = raw[i].clone();
        let mut take = || -> Result<String, String> {
            i += 1;
            raw.get(i)
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        match flag.as_str() {
            "--network" => args.network = net::Network::parse(&take()?)?,
            "--input" => args.input = Some(read_json("--input", &take()?)?),
            "--output" => args.output = Some(read_json("--output", &take()?)?),
            "--payment-key" => args.payment_key = Some(take()?),
            "--secrets-ref" => args.secrets_ref = Some(net::parse_secrets_ref(&take()?)?),
            "--collateral" => args.collateral = Some(read_file(&take()?)?),
            "--bundle" => args.bundle_path = Some(take()?),
            "--offline" => args.offline = true,
            "--short" => args.short = true,
            "--json" => args.json = true,
            "--no-color" => args.no_color = true,
            other => return Err(format!("unknown option {other}")),
        }
        i += 1;
    }
    Ok(args)
}

fn read_file(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))
}

/// Accepts either a path or the JSON itself, because a small request body is not worth a temporary
/// file. Nothing that starts with `{` or `[` is a plausible filename, so the two never collide.
fn read_json(flag: &str, value: &str) -> Result<serde_json::Value, String> {
    let trimmed = value.trim_start();
    let (source, origin) = if trimmed.starts_with('{') || trimmed.starts_with('[') {
        (trimmed.to_string(), flag.to_string())
    } else {
        (read_file(value)?, format!("{flag} {value}"))
    };
    serde_json::from_str(&source).map_err(|e| json_error(&origin, &source, &e))
}

/// Point at the offending character instead of naming a column and leaving the reader to count.
///
/// A payload is usually pasted on a command line, where a stray brace is invisible and the shell
/// has already mangled the quoting. "trailing characters at line 1 column 110" is technically the
/// whole answer and practically useless.
fn json_error(origin: &str, source: &str, error: &serde_json::Error) -> String {
    const CONTEXT: usize = 44;

    let line_no = error.line().max(1);
    let column = error.column().max(1);
    let line = source.lines().nth(line_no - 1).unwrap_or("");

    // Window the line around the error so a long single-line body stays readable.
    let chars: Vec<char> = line.chars().collect();
    let at = (column - 1).min(chars.len());
    let start = at.saturating_sub(CONTEXT);
    let end = (at + CONTEXT).min(chars.len());
    let head = if start > 0 { "…" } else { "" };
    let tail = if end < chars.len() { "…" } else { "" };
    let excerpt: String = chars[start..end].iter().collect();
    let caret = " ".repeat(head.chars().count() + (at - start));

    let mut message = format!(
        "{origin} is not valid JSON: {error}\n\n  {head}{excerpt}{tail}\n  {caret}^ here"
    );
    if error.to_string().starts_with("trailing characters") {
        message.push_str(
            "\n\n  The value parsed as a complete JSON document before this point, so what \
             follows is extra.\n  A stray closing brace part-way through the payload is the \
             usual cause.",
        );
    }
    message
}

fn run() -> Result<ExitCode, String> {
    let args = parse_args()?;

    let style = Style::detect(args.no_color, !args.short && !args.json);
    let (attestation, mut evidence, network_name) = match args.command.as_str() {
        "bundle" => return verify_bundle(&args),
        "tx" | "call" | "job" | "run" => gather(&args, &style)?,
        other => return Err(format!("unknown command {other:?}\n\n{USAGE}")),
    };

    if args.input.is_some() {
        evidence.input = args.input.clone();
    }
    if args.output.is_some() {
        evidence.output = args.output.clone();
    }

    let verification = core::verify(&attestation, &evidence);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&verification).unwrap());
    } else if args.short {
        render::short(&style, &verification);
    } else {
        render::full(&style, &attestation, &verification, &evidence, &network_name);
    }

    // Only on request: a verification tool that drops files into whatever directory it was run
    // from is a nuisance, and the bundle is worth having deliberately rather than by accident.
    if let Some(path) = &args.bundle_path {
        let bundle = Bundle::new(&network_name, attestation, &evidence, verification.clone());
        std::fs::write(path, serde_json::to_string_pretty(&bundle).unwrap())
            .map_err(|e| format!("could not write {path}: {e}"))?;
        if !args.json {
            println!("\n  Evidence bundle written to {path}");
            println!("  Re-check it with no network at all: outlayer-verify bundle {path} --offline");
        }
    } else if !args.json && !args.short {
        println!();
        render::note(
            &style,
            "Tip: --bundle proof.json saves the record, the collateral and the payloads into one \
             file that re-verifies offline, years from now, with no network and no dependence on \
             anyone still being around.",
        );
    }

    Ok(exit_code(&verification))
}

/// Fetch the record and everything needed to judge it.
fn gather(args: &Args, style: &Style) -> Result<(core::Attestation, Evidence, String), String> {
    if args.offline {
        return Err("--offline only applies to `bundle`; the other commands must fetch the record".into());
    }
    let network = args.network;
    let network_name = match network {
        net::Network::Mainnet => "mainnet",
        net::Network::Testnet => "testnet",
    };

    let mut evidence = Evidence {
        register_contract: Some(network.register_contract().to_string()),
        ..Default::default()
    };

    let attestation = match args.command.as_str() {
        "tx" => {
            require(&args.value, "a NEAR transaction hash")?;
            render::step(style, &format!("Fetching the record for transaction {}", args.value));
            let att = net::fetch_attestation(network, net::Lookup::Transaction(&args.value))?;
            render::step_ok(style, &format!("record found: task {}", att.task_id));
            att
        }
        "call" => {
            require(&args.value, "an HTTPS call id")?;
            render::step(style, &format!("Fetching the record for call {}", args.value));
            let att = net::fetch_attestation(network, net::Lookup::Call(&args.value))?;
            render::step_ok(style, &format!("record found: task {}", att.task_id));
            att
        }
        "job" => {
            let id: i64 = args
                .value
                .parse()
                .map_err(|_| "job takes a numeric task id".to_string())?;
            render::step(style, &format!("Fetching the record for task {id}"));
            let att = net::fetch_attestation(network, net::Lookup::Task(id))?;
            render::step_ok(style, "record found");
            att
        }
        "run" => {
            require(&args.value, "a project as <owner>/<project>")?;
            let key = args
                .payment_key
                .clone()
                .ok_or("run needs --payment-key or $OUTLAYER_PAYMENT_KEY")?;
            let input = args.input.clone().unwrap_or(serde_json::json!({}));

            render::step(style, &format!("Calling {} on {network_name}", args.value));
            let outcome =
                net::call_project(network, &args.value, &key, input, args.secrets_ref.clone())?;
            render::step_ok(style, &format!("call {} — {}", outcome.call_id, outcome.status));
            if let Some(error) = &outcome.error {
                render::step_warn(style, &format!("the program reported: {error}"));
            }

            // Keep both payloads: for an HTTPS call only their hashes are stored, so this is the
            // only moment they exist anywhere outside the caller's process.
            evidence.input = Some(outcome.input.clone());
            evidence.output = outcome.output.clone();
            render::step_ok(style, "request and response captured — they cannot be recovered later");

            render::step(style, "Waiting for the worker to publish the attestation");
            let att = net::await_attestation(
                network,
                net::Lookup::Call(&outcome.call_id),
                8,
                std::time::Duration::from_secs(3),
            )?;
            render::step_ok(style, &format!("attestation published: task {}", att.task_id));
            att
        }
        _ => unreachable!(),
    };

    // An on-chain execution carries its own payloads: the request is in the contract's
    // `execution_requested` event and the response is the value the contract returned. Recovering
    // them is what makes `tx` a complete proof with nothing for the caller to keep.
    if attestation.transaction_hash.is_some() && evidence.input.is_none() {
        let tx = attestation.transaction_hash.clone().unwrap();
        match &attestation.caller_account_id {
            Some(caller) => {
                render::step(style, "Recovering the request and response from the chain");
                match net::fetch_chain_payloads(network, &tx, caller) {
                    Ok((input, output)) => {
                        match (&input, &output) {
                            (Some(_), Some(_)) => render::step_ok(style, "both recovered from the transaction"),
                            (Some(_), None) => render::step_warn(style, "request recovered, response not found in the transaction"),
                            (None, Some(_)) => render::step_warn(style, "response recovered, request not found in the transaction"),
                            (None, None) => render::step_warn(style, "neither payload appears in this transaction"),
                        }
                        evidence.input_raw = input;
                        evidence.output_raw = output;
                    }
                    Err(e) => render::step_warn(style, &format!("archival lookup failed — {e}")),
                }
            }
            None => render::step_warn(
                style,
                "the record names no caller, so the transaction cannot be looked up",
            ),
        }
    }

    // Collateral has to match the platform named inside the signed quote, and be valid at the
    // moment the execution ran — not now.
    match &args.collateral {
        Some(supplied) => {
            render::step(style, "Using the Intel collateral you supplied");
            evidence.collateral = Some(supplied.clone());
        }
        None => {
            let bytes = attestation.quote_bytes();
            if let Ok(bytes) = bytes {
                match core::quote::peek(&bytes) {
                    Ok(unverified) => {
                        render::step(
                            style,
                            &format!(
                                "Fetching Intel collateral for platform {}, valid at {}",
                                unverified.fmspc,
                                iso8601(attestation.timestamp)
                            ),
                        );
                        match net::fetch_collateral(network, &unverified.fmspc, attestation.timestamp)
                        {
                            Ok((body, info)) => {
                                if info.covers_execution_time {
                                    render::step_ok(
                                        style,
                                        &format!("published by {}, valid {} .. {}", info.contract_id, info.valid_from, info.valid_until),
                                    );
                                } else {
                                    render::step_warn(
                                        style,
                                        &format!("nearest window is {} .. {} — it does NOT cover this execution", info.valid_from, info.valid_until),
                                    );
                                }
                                evidence.collateral = Some(body);
                                evidence.collateral_info = Some(info);
                            }
                            Err(e) => render::step_warn(style, &format!("collateral unavailable — {e}")),
                        }
                    }
                    Err(e) => render::step_warn(style, &e),
                }
            }
        }
    }

    // Measurements can only be trusted once the quote verifies, so ask the chain about the ones the
    // verifier will actually decode rather than about anything the record claims.
    if let (Some(collateral), Ok(bytes)) = (&evidence.collateral, attestation.quote_bytes()) {
        if let Ok(verified) = core::quote::verify(&bytes, collateral, attestation.timestamp as u64) {
            render::step(
                style,
                &format!(
                    "Asking {} whether these measurements are approved",
                    network.register_contract()
                ),
            );
            match net::measurements_approved(network, &verified.measurements) {
                Ok(approved) => {
                    if approved {
                        render::step_ok(style, "the chain recognises this build");
                    } else {
                        render::step_warn(style, "the chain does NOT list this build as approved");
                    }
                    evidence.measurements_approved = Some(approved);
                }
                Err(e) => render::step_warn(style, &format!("could not read the approved list — {e}")),
            }
        }
    }

    Ok((attestation, evidence, network_name.to_string()))
}

fn verify_bundle(args: &Args) -> Result<ExitCode, String> {
    require(&args.value, "a path to a bundle file")?;
    let style = Style::detect(args.no_color, !args.short && !args.json);
    let bundle: Bundle = serde_json::from_str(&read_file(&args.value)?)
        .map_err(|e| format!("{}: not a bundle: {e}", args.value))?;
    if bundle.bundle_format != core::bundle::BUNDLE_FORMAT {
        return Err(format!(
            "bundle format {} was written by a different version of this tool",
            bundle.bundle_format
        ));
    }

    // Recomputed from the evidence in the file, never read from the verdict stored in it.
    let verification = core::verify(&bundle.attestation, &bundle.evidence());
    if args.json {
        println!("{}", serde_json::to_string_pretty(&verification).unwrap());
    } else if args.short {
        render::short(&style, &verification);
    } else {
        render::full(&style, &bundle.attestation, &verification, &bundle.evidence(), &bundle.network);
    }
    Ok(exit_code(&verification))
}

fn require(value: &str, what: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("expected {what}\n\n{USAGE}"));
    }
    Ok(())
}

fn exit_code(v: &Verification) -> ExitCode {
    if v.has_failure() {
        ExitCode::from(1)
    } else if v.is_proven() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

/// Minimal UTC formatting — a date is not worth a chrono dependency in a tool whose value is that
/// its dependency list can be read in one sitting.
pub fn iso8601(unix: i64) -> String {
    let days = unix.div_euclid(86_400);
    let secs = unix.rem_euclid(86_400);
    let (mut year, mut day) = (1970, days);
    loop {
        let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
        let len = if leap { 366 } else { 365 };
        if day < len {
            break;
        }
        day -= len;
        year += 1;
    }
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let months = [
        31,
        if leap { 29 } else { 28 },
        31, 30, 31, 30, 31, 31, 30, 31, 30, 31,
    ];
    let mut month = 0;
    while day >= months[month] {
        day -= months[month];
        month += 1;
    }
    format!(
        "{year:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        month + 1,
        day + 1,
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}
