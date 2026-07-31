# outlayer-verify

Check for yourself that an [OutLayer](https://outlayer.fastnear.com) execution really happened: that
it ran inside genuine Intel TDX hardware, that the code was a build approved on the NEAR blockchain,
and that it produced *your* output from *your* input.

The tool takes no account, no configuration file and no key material. The Intel root certificate it
checks signatures against is compiled into the binary rather than fetched, so nobody — including us
— can change the answer by changing what it downloads.

```sh
# an execution you triggered from a NEAR transaction
outlayer-verify tx 8xK2vN9pQr...

# an HTTPS call: run it and prove it in one step
outlayer-verify run alice.near/my-agent --input request.json --payment-key "$KEY"
```

## What it proves

| Layer | Question | How |
|---|---|---|
| **Authenticity** | Is this a genuine Intel TDX quote? | Signature chain to Intel's root, against Intel-signed collateral valid at the time of execution |
| **Identity** | Is this code the operator published? | Measurements from the *verified* quote against `is_measurements_approved` on the register contract |
| **Binding** | Does the quote cover *this* execution? | The task's fields are hashed into `report_data` before signing; the tool recomputes that hash |

Every layer reports one of three verdicts. `UNPROVEN` is not a softened failure — it means a
specific question could not be answered, and the tool says which one and why. A verifier that only
ever says yes or no will eventually say yes to something it did not check.

## What it does not prove

- **That the approved measurement was built from the published source.** That requires a
  reproducible build and a `digest → commit` map. Until those exist, a passing verdict means "the
  operator's approved build ran", not "the source you read ran".
- **That the operator cannot approve a build of their choosing.** The tool reports *which* account
  holds the approved list. Who controls that account, and under what governance, is a separate
  question you should ask.
- **Anything about an execution in a period no collateral covers.** Intel serves only current TCB
  data, so if the operator failed to archive collateral for some window, executions inside it can
  never be verified as of their own time. The tool says so rather than quietly verifying against a
  neighbouring window.
- **That the program's logic is correct**, or that the output is useful. Only that this output is
  what that computation produced.

## Installing

```sh
cargo install --git https://github.com/out-layer/outlayer-verify outlayer-verify
```

## Usage

```
outlayer-verify tx <near-tx-hash>        prove an on-chain execution
outlayer-verify call <call-id>           prove an HTTPS execution
outlayer-verify job <task-id>            prove by internal task id (what dashboard links carry)
outlayer-verify run <owner>/<project>    execute, capture the payloads, then prove
outlayer-verify bundle <file.json>       re-check a saved bundle
```

Options: `--network mainnet|testnet`, `--input <file>`, `--output <file>`, `--payment-key`,
`--collateral <file>`, `--bundle <file>`, `--offline`, `--short`, `--json`, `--no-color`.

Exit codes: `0` proven, `1` a layer failed, `2` unproven, `3` usage error. Suitable for CI.

### Reading the output

By default the tool shows its working, because a verdict you cannot take apart is only a different
way of saying "trust me". It logs each step as it happens, prints the record as published, then what
is actually inside the signed quote, then the collateral it used and why that collateral applies —
and for every comparison it prints **both** values:

```
── Checks ──────────────────────────────────────────────────────────────

  [ PASS     ] Authenticity  is this a genuine Intel TDX quote?
                         Intel signature chain valid, TCB UpToDate
    Intel TCB status     UpToDate

  [ PASS     ] Identity  is this code approved on chain?
                         measurements approved on worker.outlayer.near

  [ FAIL     ] Binding  does the quote cover this execution?
    fields hash to       4b243baa79cdbe2104649332cd4bc3544d330e3eee68056755628c73645b207f
    quote commits to     7d19e4dcb6e3b36ff6f5e62580224e956fec8adac57e54156befc2c263c57efe — DIFFERENT
```

`--short` collapses everything to one line for scripts and repeat runs:

```
$ outlayer-verify job 205123 --short
PROVEN task 205123 (execute) 7d19e4dcb6e3b36f…63c57efe
```

`--json` prints the same values as a machine-readable object. Colour switches itself off when the
output is not a terminal, and honours `NO_COLOR`.

Nothing is written to disk unless you ask for it with `--bundle`.

### Keep your payloads

For an on-chain execution the input and output can be recovered from NEAR archival RPC forever. For
an HTTPS call **only their hashes are ever stored** — if you did not keep the request and the
response, that execution can never be fully verified again, by anyone, including the operator.

This is why `run` exists: it performs the call and keeps both payloads, so the proof is possible at
all. If you call the API directly, save what you sent and what you got back.

### The evidence bundle

`--bundle <file>` writes a single self-contained JSON file: the record, the Intel-signed collateral
used, the payloads, the chain's answer, and the verdict. Re-check it years later with no
network and no dependence on anyone still being around:

```sh
outlayer-verify job 205123 --bundle proof.json
outlayer-verify bundle proof.json --offline
```

The stored verdict is informational — `bundle` recomputes it from the evidence rather than believing
it. Altering the collateral breaks the Intel signature chain, so including it here gives whoever
wrote the file no influence over the result.

## Reporting a failure

A `FAIL` verdict on a record served by the official API is a security finding, not a bug in your
setup. Please send the evidence bundle to `security@outlayer.ai` before publishing it.

## Development

```sh
cargo test        # includes real production records as fixtures
cargo build --release
```

The test vectors are genuine attestations pulled from mainnet and testnet, including one from 53
minutes before the attestation-format cut-off, so the boundary is pinned from both sides rather than
assumed.

## Licence

Apache-2.0.
