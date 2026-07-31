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
`--collateral <file>`, `--bundle <file>`, `--no-bundle`, `--offline`, `--json`.

Exit codes: `0` proven, `1` a layer failed, `2` unproven, `3` usage error. Suitable for CI.

### Keep your payloads

For an on-chain execution the input and output can be recovered from NEAR archival RPC forever. For
an HTTPS call **only their hashes are ever stored** — if you did not keep the request and the
response, that execution can never be fully verified again, by anyone, including the operator.

This is why `run` exists: it performs the call and keeps both payloads, so the proof is possible at
all. If you call the API directly, save what you sent and what you got back.

### The evidence bundle

Every successful run writes a single self-contained JSON file: the record, the Intel-signed
collateral used, the payloads, the chain's answer, and the verdict. Re-check it years later with no
network and no dependence on anyone still being around:

```sh
outlayer-verify bundle outlayer-proof-205123.json --offline
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
