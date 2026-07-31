//! `outlayer-verify` — check an OutLayer execution proof yourself.
//!
//! No account, no config file, no key material. Everything the tool needs is an argument, and the
//! Intel root certificate it checks signatures against is compiled in rather than fetched.

use std::process::ExitCode;

use outlayer_verify_core as core;
use outlayer_verify_core::{bundle::Bundle, net, Evidence, Layer, Verification};

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
  --input <file>                the request you sent (HTTPS executions), or the body for `run`
  --output <file>               the response you received (HTTPS executions)
  --payment-key <key>           OWNER:NONCE:KEY, for `run`; or $OUTLAYER_PAYMENT_KEY
  --collateral <file>           use your own copy of the Intel collateral
  --bundle <file>               where to write the evidence bundle (default: alongside the result)
  --no-bundle                   do not write one
  --offline                     no network at all; only valid with `bundle`
  --json                        machine-readable result instead of the table
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
    collateral: Option<String>,
    bundle_path: Option<String>,
    no_bundle: bool,
    offline: bool,
    json: bool,
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
        collateral: None,
        bundle_path: None,
        no_bundle: false,
        offline: false,
        json: false,
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
            "--input" => args.input = Some(read_json(&take()?)?),
            "--output" => args.output = Some(read_json(&take()?)?),
            "--payment-key" => args.payment_key = Some(take()?),
            "--collateral" => args.collateral = Some(read_file(&take()?)?),
            "--bundle" => args.bundle_path = Some(take()?),
            "--no-bundle" => args.no_bundle = true,
            "--offline" => args.offline = true,
            "--json" => args.json = true,
            other => return Err(format!("unknown option {other}")),
        }
        i += 1;
    }
    Ok(args)
}

fn read_file(path: &str) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))
}

fn read_json(path: &str) -> Result<serde_json::Value, String> {
    serde_json::from_str(&read_file(path)?).map_err(|e| format!("{path}: not valid JSON: {e}"))
}

fn run() -> Result<ExitCode, String> {
    let args = parse_args()?;

    let (attestation, mut evidence, network_name) = match args.command.as_str() {
        "bundle" => return verify_bundle(&args),
        "tx" | "call" | "job" | "run" => gather(&args)?,
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
    } else {
        render(&attestation, &verification);
    }

    if !args.no_bundle {
        let path = args.bundle_path.clone().unwrap_or_else(|| {
            format!("outlayer-proof-{}.json", attestation.task_id)
        });
        let bundle = Bundle::new(&network_name, attestation, &evidence, verification.clone());
        std::fs::write(&path, serde_json::to_string_pretty(&bundle).unwrap())
            .map_err(|e| format!("could not write {path}: {e}"))?;
        if !args.json {
            println!("\n  Evidence bundle: {path}");
            println!("  Re-check it any time, with no network: outlayer-verify bundle {path} --offline");
        }
    }

    Ok(exit_code(&verification))
}

/// Fetch the record and everything needed to judge it.
fn gather(args: &Args) -> Result<(core::Attestation, Evidence, String), String> {
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
            net::fetch_attestation(network, net::Lookup::Transaction(&args.value))?
        }
        "call" => {
            require(&args.value, "an HTTPS call id")?;
            net::fetch_attestation(network, net::Lookup::Call(&args.value))?
        }
        "job" => {
            let id: i64 = args
                .value
                .parse()
                .map_err(|_| "job takes a numeric task id".to_string())?;
            net::fetch_attestation(network, net::Lookup::Task(id))?
        }
        "run" => {
            require(&args.value, "a project as <owner>/<project>")?;
            let key = args
                .payment_key
                .clone()
                .ok_or("run needs --payment-key or $OUTLAYER_PAYMENT_KEY")?;
            let input = args.input.clone().unwrap_or(serde_json::json!({}));

            println!("Calling {} on {network_name}...", args.value);
            let outcome = net::call_project(network, &args.value, &key, input)?;
            println!("  call_id: {}", outcome.call_id);
            println!("  status : {}", outcome.status);
            if let Some(error) = &outcome.error {
                println!("  error  : {error}");
            }

            // Keep both payloads: for an HTTPS call only their hashes are stored, so this is the
            // only moment they exist anywhere outside the caller's process.
            evidence.input = Some(outcome.input.clone());
            evidence.output = outcome.output.clone();

            println!("  waiting for the attestation to be published...");
            net::await_attestation(
                network,
                net::Lookup::Call(&outcome.call_id),
                8,
                std::time::Duration::from_secs(3),
            )?
        }
        _ => unreachable!(),
    };

    // Collateral has to match the platform named inside the signed quote, and be valid at the
    // moment the execution ran — not now.
    match &args.collateral {
        Some(supplied) => evidence.collateral = Some(supplied.clone()),
        None => {
            let bytes = attestation.quote_bytes();
            if let Ok(bytes) = bytes {
                match core::quote::peek(&bytes) {
                    Ok(unverified) => {
                        match net::fetch_collateral(network, &unverified.fmspc, attestation.timestamp)
                        {
                            Ok((body, info)) => {
                                evidence.collateral = Some(body);
                                evidence.collateral_info = Some(info);
                            }
                            Err(e) => eprintln!("note: collateral unavailable — {e}"),
                        }
                    }
                    Err(e) => eprintln!("note: {e}"),
                }
            }
        }
    }

    // Measurements can only be trusted once the quote verifies, so ask the chain about the ones the
    // verifier will actually decode rather than about anything the record claims.
    if let (Some(collateral), Ok(bytes)) = (&evidence.collateral, attestation.quote_bytes()) {
        if let Ok(verified) = core::quote::verify(&bytes, collateral, attestation.timestamp as u64) {
            match net::measurements_approved(network, &verified.measurements) {
                Ok(approved) => evidence.measurements_approved = Some(approved),
                Err(e) => eprintln!("note: could not read the approved list — {e}"),
            }
        }
    }

    Ok((attestation, evidence, network_name.to_string()))
}

fn verify_bundle(args: &Args) -> Result<ExitCode, String> {
    require(&args.value, "a path to a bundle file")?;
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
    } else {
        render(&bundle.attestation, &verification);
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

fn render(att: &core::Attestation, v: &Verification) {
    let when = iso8601(att.timestamp);
    println!("\nOutLayer execution proof — task {} ({}), {when}", v.task_id, v.task_type);
    println!();
    line("Authenticity", &v.authenticity);
    if let Some(status) = &v.tcb_status {
        detail(&format!("Intel TCB status {status}"));
    }
    if let Some(info) = &v.collateral {
        detail(&format!(
            "platform {} · collateral published by {}{}",
            info.fmspc,
            info.contract_id,
            info.tx_hash
                .as_ref()
                .map(|t| format!(", tx {t}"))
                .unwrap_or_default()
        ));
    }
    line("Identity", &v.identity);
    if let Some(m) = &v.measurements {
        detail(&format!("RTMR3 {}", short(&m.rtmr3)));
    }
    line("Binding", &v.binding);
    if let Some(input) = &v.input {
        line("  input", input);
    }
    if let Some(output) = &v.output {
        line("  output", output);
    }

    println!();
    if v.is_proven() {
        println!("  PROVEN — this input produced this output inside genuine Intel TDX hardware");
        println!("           running code approved on chain.");
    } else if v.has_failure() {
        println!("  NOT PROVEN — a check failed. Do not treat this execution as verified.");
    } else {
        println!("  INCOMPLETE — no check failed, but the proof is not complete either. See above.");
    }

    if !v.uncovered_fields.is_empty() {
        println!(
            "\n  Not covered by the signature on this record ({}): {}",
            "pre-V1 format",
            v.uncovered_fields.join(", ")
        );
    }
    println!("  Not proven by any attestation: that the approved measurement was built from the");
    println!("  published source. That needs a reproducible build, which is a separate claim.");
}

fn line(name: &str, layer: &Layer) {
    let (label, text) = match layer {
        Layer::Pass { detail } => ("PASS", detail.as_str()),
        Layer::Fail { reason } => ("FAIL", reason.as_str()),
        Layer::Unproven { reason } => ("UNPROVEN", reason.as_str()),
    };
    println!("  {name:<14} {label:<9} {}", wrap(text));
}

fn detail(text: &str) {
    println!("  {:<14} {:<9} {}", "", "", wrap(text));
}

/// Keep long explanations readable in a terminal without depending on a wrapping crate.
fn wrap(text: &str) -> String {
    const WIDTH: usize = 62;
    // Matches the "  " + 14-wide name + " " + 9-wide verdict + " " prefix, so a wrapped
    // explanation lines up under the first word instead of drifting.
    const INDENT: &str = "\n                          ";
    let mut out = String::new();
    let mut column = 0;
    for word in text.split_whitespace() {
        if column > 0 && column + word.len() + 1 > WIDTH {
            out.push_str(INDENT);
            column = 0;
        } else if column > 0 {
            out.push(' ');
            column += 1;
        }
        out.push_str(word);
        column += word.len();
    }
    out
}

fn short(hex: &str) -> String {
    if hex.len() > 20 {
        format!("{}…{}", &hex[..8], &hex[hex.len() - 4..])
    } else {
        hex.to_string()
    }
}

/// Minimal UTC formatting — a date is not worth a chrono dependency in a tool whose value is that
/// its dependency list can be read in one sitting.
fn iso8601(unix: i64) -> String {
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
