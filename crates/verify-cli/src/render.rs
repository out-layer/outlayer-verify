//! Terminal output.
//!
//! A verdict a reader cannot take apart is only a different way of saying "trust me", so the
//! default output shows the working: which record was fetched, what the quote actually contains,
//! which collateral was used and why it applies, and — for every comparison — both values that were
//! compared. `--short` collapses all of it to the conclusion for scripts and repeat runs.

use std::io::IsTerminal;

use outlayer_verify_core::{Attestation, Evidence, Layer, Verification};

pub struct Style {
    colour: bool,
    /// False in `--short` and `--json`: those modes exist to produce one parseable answer, and a
    /// progress log ahead of it defeats the point.
    steps: bool,
}

impl Style {
    /// Colour when a human is watching. Honours NO_COLOR (https://no-color.org) and switches off
    /// when the output is piped, so a log file never fills with escape codes.
    pub fn detect(forced_off: bool, steps: bool) -> Self {
        Style {
            colour: !forced_off
                && std::env::var_os("NO_COLOR").is_none()
                && std::io::stdout().is_terminal(),
            steps,
        }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.colour {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    pub fn pass(&self, t: &str) -> String { self.paint("32;1", t) }
    pub fn fail(&self, t: &str) -> String { self.paint("31;1", t) }
    pub fn warn(&self, t: &str) -> String { self.paint("33;1", t) }
    pub fn head(&self, t: &str) -> String { self.paint("1", t) }
    pub fn dim(&self, t: &str) -> String { self.paint("2", t) }

    /// Fixed width so the verdicts line up in a column and the eye finds the odd one out.
    fn verdict_badge(&self, layer: &Layer) -> String {
        match layer {
            Layer::Pass { .. } => self.pass("[ PASS     ]"),
            Layer::Fail { .. } => self.fail("[ FAIL     ]"),
            Layer::Unproven { .. } => self.warn("[ UNPROVEN ]"),
        }
    }
}

const KEY_WIDTH: usize = 20;
/// Where a wrapped value continues: two leading spaces, the key column, three separating spaces.
const VALUE_COLUMN: usize = 2 + KEY_WIDTH + 3;
const WRAP_AT: usize = 96;

pub fn section(style: &Style, title: &str) {
    println!("\n{}", style.head(&format!("── {title} ")).to_string() + &style.dim(&"─".repeat(WRAP_AT.saturating_sub(title.len() + 4))));
}

/// One `key: value` line. A value too long for the terminal continues under the value column, not
/// under the key, so a column of hashes stays scannable.
pub fn kv(key: &str, value: &str) {
    if value.is_empty() {
        return;
    }
    let indent = " ".repeat(VALUE_COLUMN);
    let mut first = true;
    for line in wrapped(value, WRAP_AT - VALUE_COLUMN) {
        if first {
            println!("  {key:<KEY_WIDTH$}   {line}");
            first = false;
        } else {
            println!("{indent}{line}");
        }
    }
}

/// A block of prose indented to a given column.
pub fn para(indent: usize, text: &str) {
    let pad = " ".repeat(indent);
    for line in wrapped(text, WRAP_AT - indent) {
        println!("{pad}{line}");
    }
}

/// Greedy wrap. Values with no spaces (hashes) are left intact rather than broken mid-hex, since a
/// hash split across lines cannot be compared by eye or copied in one go.
fn wrapped(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        if !line.is_empty() && line.len() + word.len() + 1 > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

pub fn note(style: &Style, text: &str) {
    for line in wrapped(text, WRAP_AT - 2) {
        println!("  {}", style.dim(&line));
    }
}

/// A step in the process, printed as it happens so a slow or failing stage is visible.
pub fn step(style: &Style, text: &str) {
    if style.steps {
        println!("{} {text}", style.dim("▸"));
    }
}

pub fn step_ok(style: &Style, text: &str) {
    if style.steps {
        println!("  {} {text}", style.pass("✓"));
    }
}

/// Always shown: a step that did not go to plan changes how the verdict should be read, so it is
/// not something `--short` may swallow. Goes to stderr so it cannot corrupt piped output.
pub fn step_warn(style: &Style, text: &str) {
    if style.steps {
        println!("  {} {text}", style.warn("!"));
    } else {
        eprintln!("warning: {text}");
    }
}

fn short_hex(value: &str) -> String {
    if value.len() > 24 {
        format!("{}…{}", &value[..16], &value[value.len() - 8..])
    } else {
        value.to_string()
    }
}

/// The full report: the record, the quote, the collateral, then the three layers.
pub fn full(style: &Style, att: &Attestation, v: &Verification, ev: &Evidence, network: &str) {
    section(style, "Record as published");
    kv("task id", &att.task_id.to_string());
    kv("task type", &att.task_type);
    kv("executed at", &format!("{} ({})", crate::iso8601(att.timestamp), att.timestamp));
    kv(
        "format",
        match v.format {
            outlayer_verify_core::Format::V1 => "V1 — commits to caller, project, secrets, timestamp and payment",
            outlayer_verify_core::Format::Legacy => "legacy — see the scope section at the end",
        },
    );
    kv("network", network);
    if let Some(tx) = &att.transaction_hash {
        kv("transaction", tx);
    }
    if let Some(height) = att.block_height {
        kv("block height", &height.to_string());
    }
    if let Some(call) = &att.call_id {
        kv("call id", call);
    }
    if let Some(caller) = &att.caller_account_id {
        kv("caller", caller);
    }
    if let Some(project) = &att.project_id {
        kv("project", project);
    }
    if let Some(repo) = &att.repo_url {
        kv("source repo", repo);
    }
    if let Some(commit) = &att.commit_hash {
        kv("commit", commit);
    }
    if let Some(target) = &att.build_target {
        kv("build target", target);
    }
    if let Some(wasm) = &att.wasm_hash {
        kv("wasm sha256", wasm);
    }
    if let Some(input) = &att.input_hash {
        kv("input sha256", input);
    }
    kv("output sha256", &att.output_hash);
    if let Some(usd) = &att.attached_usd {
        kv("attached payment", usd);
    }
    if let Some(secrets) = &att.secrets_ref {
        kv("secrets ref", secrets);
    }

    if v.measurements.is_some() || v.quote_size.is_some() {
        section(style, "Inside the signed quote");
        note(style, "read from the quote AFTER Intel's signature was checked, not from the record");
        if let Some(size) = v.quote_size {
            kv("size", &format!("{size} bytes"));
        }
        if let Some(info) = &v.collateral {
            kv("platform (FMSPC)", &format!("{} — taken from the signed PCK certificate", info.fmspc));
        }
        if let Some(m) = &v.measurements {
            kv("MRTD", &m.mrtd);
            kv("RTMR0", &m.rtmr0);
            kv("RTMR1", &m.rtmr1);
            kv("RTMR2", &m.rtmr2);
            kv("RTMR3", &m.rtmr3);
        }
        if let Some(prefix) = &v.report_data_prefix {
            kv("report_data[..32]", prefix);
        }
        if let Some(suffix) = &v.report_data_suffix {
            let zero = suffix.chars().all(|c| c == '0');
            kv(
                "report_data[32..]",
                &format!("{suffix} ({})", if zero { "zero, as the format requires" } else { "NOT zero" }),
            );
        }
    }

    if let Some(info) = &v.collateral {
        section(style, "Intel collateral used");
        note(style, "Intel-signed TCB data; altering it breaks the chain, so its source cannot change the verdict");
        kv("published by", &info.contract_id);
        if let Some(tx) = &info.tx_hash {
            kv("in transaction", tx);
        }
        if let Some(block) = info.block_height {
            kv("at block", &block.to_string());
        }
        kv("sha256", &info.collateral_sha256);
        kv("valid from", &info.valid_from);
        kv("valid until", &info.valid_until);
        kv(
            "covers execution",
            if info.covers_execution_time {
                "yes — this execution falls inside the validity window"
            } else {
                "NO — verified against the nearest window instead; see the verdict"
            },
        );
        kv("recovered from", &info.source);
    }

    section(style, "Checks");
    check(style, "Authenticity", "is this a genuine Intel TDX quote?", &v.authenticity);
    if let Some(status) = &v.tcb_status {
        kv("  Intel TCB status", status);
    }
    if !v.advisory_ids.is_empty() {
        kv("  advisories", &v.advisory_ids.join(", "));
    }

    check(style, "Identity", "is this code approved on chain?", &v.identity);

    check(style, "Binding", "does the quote cover this execution?", &v.binding);
    kv("  fields hash to", &v.expected_task_hash);
    if let Some(prefix) = &v.report_data_prefix {
        kv(
            "  quote commits to",
            &format!(
                "{prefix}  {}",
                if prefix == &v.expected_task_hash { "— identical" } else { "— DIFFERENT" }
            ),
        );
    }

    if let Some(layer) = &v.input {
        check(style, "Input", "do the request bytes match what was attested?", layer);
        payload_body(style, ev.input_raw.clone().or_else(|| ev.input.as_ref().map(|v| v.to_string())));
        if let Some(computed) = &v.input_hash_computed {
            kv("  hashes to", computed);
            kv("  attested", att.input_hash.as_deref().unwrap_or("<none>"));
            signed_note(style, v);
        }
    }
    if let Some(layer) = &v.output {
        check(style, "Output", "do the response bytes match what was attested?", layer);
        payload_body(style, ev.output_raw.clone().or_else(|| ev.output.as_ref().map(|v| v.to_string())));
        if let Some(computed) = &v.output_hash_computed {
            kv("  hashes to", computed);
            kv("  attested", &att.output_hash);
            signed_note(style, v);
        }
    }

    verdict_block(style, v);
    caveats(style, v, att);
}

/// Why matching the attested hash means anything.
///
/// On its own, "these bytes hash to the value in the record" only says the record is
/// self-consistent — whoever wrote the record could have written both. What makes it a proof is
/// that `input_hash` and `output_hash` are themselves part of the commitment inside the signed
/// quote, checked by the Binding layer. Without saying so, a reader has to already know the format
/// to see the difference, which is exactly the knowledge they came here not needing.
fn signed_note(style: &Style, v: &Verification) {
    let text = if v.binding.is_pass() {
        "the attested value is itself inside the signed quote — it is part of the commitment \
         checked by Binding above, so matching it means matching what the TEE signed"
    } else {
        "note: Binding did not pass, so the attested value above is not backed by the signature"
    };
    para(VALUE_COLUMN, &style.dim(text));
}

/// The payload itself. Two matching hashes prove the bytes are the attested ones; seeing the bytes
/// is what tells the reader whether those are the bytes they meant to send.
fn payload_body(style: &Style, body: Option<String>) {
    const LIMIT: usize = 600;
    let body = match body {
        Some(text) if !text.is_empty() => text,
        _ => return,
    };
    if body.chars().count() <= LIMIT {
        kv("  content", &body);
    } else {
        let head: String = body.chars().take(LIMIT).collect();
        kv("  content", &head);
        para(
            VALUE_COLUMN,
            &style.dim(&format!("… {} more characters, full text in --bundle", body.chars().count() - LIMIT)),
        );
    }
}

fn check(style: &Style, name: &str, question: &str, layer: &Layer) {
    let text = match layer {
        Layer::Pass { detail } => detail,
        Layer::Fail { reason } => reason,
        Layer::Unproven { reason } => reason,
    };
    println!(
        "\n  {} {}  {}",
        style.verdict_badge(layer),
        style.head(name),
        style.dim(question)
    );
    para(VALUE_COLUMN, text);
}

pub fn verdict_block(style: &Style, v: &Verification) {
    println!();
    if v.is_proven() {
        println!(
            "  {}  every check passed: this input produced this output, inside genuine",
            style.pass("PROVEN")
        );
        println!("          Intel TDX hardware, running code approved on chain.");
    } else if v.has_failure() {
        println!(
            "  {}  a check failed. Do not treat this execution as verified — see the",
            style.fail("NOT PROVEN")
        );
        println!("              FAIL line above for what disagreed.");
    } else {
        println!(
            "  {}  nothing failed, but the proof is incomplete: a question above could",
            style.warn("INCOMPLETE")
        );
        println!("              not be answered. It is not evidence of wrongdoing, and it is not");
        println!("              evidence of correctness either.");
    }
}

/// Gaps that belong to *this* verification rather than to attestation in general.
///
/// The standing limits of the technique live in the README; repeating them under every run trains
/// the reader to skip the block, and then the record-specific gaps below get skipped with them.
fn caveats(style: &Style, v: &Verification, att: &Attestation) {
    if att.transaction_hash.is_some() && v.input.is_none() {
        println!();
        note(
            style,
            "The request and response could not be recovered from the transaction, so the bytes \
             themselves were not checked — only the hashes the quote commits to.",
        );
    }
    if att.call_id.is_some() && v.input.is_none() {
        println!();
        note(
            style,
            "The request and response bytes were not checked — only their hashes are stored for \
             HTTPS calls. Pass --input and --output, or use `outlayer-verify run`.",
        );
    }
    if !v.uncovered_fields.is_empty() {
        println!();
        note(
            style,
            &format!(
                "This record predates the current attestation format: {} are not part of the \
                 signed commitment, so the values shown for them are published claims.",
                v.uncovered_fields.join(", ")
            ),
        );
    }
}

/// One line, for scripts and for the second time you run it.
pub fn short(style: &Style, v: &Verification) {
    let (label, tail) = if v.is_proven() {
        (style.pass("PROVEN"), String::new())
    } else if v.has_failure() {
        let which = [
            ("authenticity", &v.authenticity),
            ("identity", &v.identity),
            ("binding", &v.binding),
        ]
        .into_iter()
        .filter(|(_, l)| l.is_fail())
        .map(|(n, _)| n)
        .collect::<Vec<_>>()
        .join(", ");
        (style.fail("NOT PROVEN"), format!(" — failed: {which}"))
    } else {
        (style.warn("INCOMPLETE"), String::new())
    };
    println!(
        "{label} task {} ({}) {}{tail}",
        v.task_id,
        v.task_type,
        short_hex(&v.expected_task_hash)
    );
}
