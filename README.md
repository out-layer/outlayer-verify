# outlayer-verify

Check for yourself that an [OutLayer](https://outlayer.fastnear.com) execution really happened: that
it ran inside genuine Intel TDX hardware, that the code was a build approved on the NEAR blockchain,
and that it produced *your* output from *your* input.

The tool takes no account, no configuration file and no key material. The Intel root certificate it
checks signatures against is compiled into the binary rather than fetched, so nobody — including us
— can change the answer by changing what it downloads.

```sh
# a live production execution — no account, no key, no payment
outlayer-verify job 221092 --network mainnet

# an execution you triggered from a NEAR transaction — nothing else needed
outlayer-verify tx 8xK2vN9pQr... --network testnet

# an HTTPS call: run it and prove it in one step
outlayer-verify run alice.near/my-agent --input '{"city":"Buenos Aires"}' --payment-key "$KEY"
```

> Lookup by **transaction hash** and by **call id** is live on testnet and ships to mainnet with the
> next coordinator release. `job <task-id>` works on both today, and the tool says which case it hit
> rather than returning a bare 404.

## Where its inputs come from

Two of the four come from us, and the honest framing is not "we give you nothing" but "nothing we
give you can change the answer":

| Input | Source | Why we cannot bend it |
|---|---|---|
| The attestation record, including the quote | our API | the quote is Intel-signed and its `report_data` binds every field in the record, so altering any of them fails a check rather than going unnoticed |
| Intel collateral for the right period | **the register contract**, read from a NEAR archival node | our API only supplies the block number to look in, and the tool reports whether the API's own copy matched the chain's byte for byte |
| The approved-build list | NEAR RPC | on-chain, not ours |
| Input and output of an on-chain call | NEAR archival RPC | in the transaction, not ours |

Intel's root certificate is compiled into the binary rather than fetched, which is what makes the
first row safe: a chain that does not terminate at that key fails regardless of who served it. The
record is the artifact under scrutiny, not a statement to be believed — we can decline to serve one,
which is an availability problem, but we cannot forge one.

Even the block-number hint is checkable: point it at the wrong block and the collateral found there
has a validity window that fails to cover the execution, which the verdict reports rather than
swallows.

None of the defaults is load-bearing either. Point the chain reads at your own node, the record at a
coordinator you host, the collateral at your own copy — the verdict should not move:

```sh
outlayer-verify tx <hash> --network testnet \
  --rpc https://rpc.testnet.near.org \
  --archival-rpc https://archival-rpc.testnet.near.org
```

If a verdict ever *does* change with the endpoint, that is a finding worth reporting.

## What it proves

| Layer | Question | How |
|---|---|---|
| **Authenticity** | Is this a genuine Intel TDX quote? | Signature chain to Intel's root, against Intel-signed collateral valid at the time of execution |
| **Identity** | Is this code the operator published? | Measurements from the *verified* quote against `is_measurements_approved` on the register contract |
| **Binding** | Does the quote cover *this* execution? | The task's fields are hashed into `report_data` before signing; the tool recomputes that hash |

Every layer reports one of three verdicts. `UNPROVEN` is not a softened failure — it means a
specific question could not be answered, and the tool says which one and why. A verifier that only
ever says yes or no will eventually say yes to something it did not check.

### What "Intel signature chain valid" covers

The Authenticity layer is a single verdict over eight checks that all have to succeed, performed by
`dcap-qvl` against the Intel root committed in this repository:

1. **TCB Info signature** — Intel root → TCB signing certificate → the TCB Info document
2. **QE Identity signature** — Intel root → QE Identity signing certificate → the document
3. **PCK certificate chain** — Intel root → PCK CA → the platform's PCK certificate
4. **QE Report signature** — the PCK certificate signs the quoting enclave's report
5. **QE Report content** — its hash covers the attestation key and auth data
6. **QE Report policy** — its fields satisfy the QE Identity policy
7. **ISV Report signature** — the attestation key signs the enclave's own report
8. **Platform TCB match** — the PCK certificate's CPU_SVN, PCE_SVN and FMSPC against TCB Info

The report ticks all eight on a pass. It does so because the library verifies all of them or returns
an error — there is no partial state — so a tick means that check succeeded. On a failure none are
ticked: which one broke is in the error, and a tick beside a check that did not run would be the one
lie this tool exists to make impossible.

The trust anchor is committed at
`crates/verify-core/src/Intel_SGX_Provisioning_Certification_RootCA.der` and compiled in with
`include_bytes!`; nothing is fetched at runtime, because a verifier that downloads its own root can
be pointed at a different one. The report prints its SHA-256, which is a disclosure rather than a
proof: it tells you which anchor that build used, and a program can print any string. It is worth
something only against a binary you trust — so build from source, or compare the committed file with
[Intel's published copy](https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.cer):

```sh
shasum -a 256 crates/verify-core/src/Intel_SGX_Provisioning_Certification_RootCA.der
# 44a0196b2b99f889b8e149e95b807a350e7424964399e885a7cbb8ccfab674d3
```

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

Options: `--network mainnet|testnet`, `--input <file|json>`, `--output <file|json>`,
`--payment-key`, `--secrets-ref <account/profile>`, `--collateral <file>`, `--api <url>`,
`--rpc <url>`, `--archival-rpc <url>`, `--bundle <file>`, `--offline`, `--short`, `--json`,
`--no-color`.

Exit codes: `0` proven, `1` a layer failed, `2` unproven, `3` usage error. Suitable for CI.

### Worked examples

**A live production execution.** Ref Finance calls a price oracle running on OutLayer; anyone can
check one of those executions without an account, a key or a payment:

```sh
outlayer-verify job 221092 --network mainnet
```

<details>
<summary>The whole output of that command &mdash; click to expand</summary>

```
$ outlayer-verify job 221092 --network mainnet

▸ Fetching the record for task 221092
  ✓ record found
▸ Fetching Intel collateral for platform b0c06f000000, valid at 2026-07-31T09:36:32Z
  ✓ published by worker.outlayer.near, valid 2026-07-21T00:13:24Z .. 2026-08-19T23:51:19Z
▸ Asking worker.outlayer.near whether these measurements are approved
  ✓ the chain recognises this build

── Record as published ─────────────────────────────────────────────────────────────────────────
  task id                221092
  task type              execute
  executed at            2026-07-31T09:36:32Z (1785490592)
  format                 V1 — commits to caller, project, secrets, timestamp and payment
  network                mainnet
  call id                8fdb7a5b-579f-4854-91f1-659a9a8e731c
  caller                 ref-labs.near
  project                price-oracle.near/price-oracle
  build target           wasm32-wasip2
  wasm sha256            3ff2c6fb9241ad4f5a3a40298b78d68b4da31b6760ecea3d5253579ec33809e7
  input sha256           832f0aa124f7f4c39c5b47e370680356c0ec105a4df232ea1cb91bf2954e6f2f
  output sha256          7c27847fa9387d25f5f459ddb9e55423a8cf53ef724eb93286d2f369d093e1c5
  attached payment       0
  secrets ref            price-oracle.near/oracle

── Inside the signed quote ─────────────────────────────────────────────────────────────────────
  read from the quote AFTER Intel's signature was checked, not from the record
  size                   5006 bytes
  platform (FMSPC)       b0c06f000000 — taken from the signed PCK certificate
  MRTD                   7fe60787222bd394cb516abca2435f22f035ab2cc9c0a4b4b3b148e46297f3d931a237b72f359052c6e657d8c1409173
  RTMR0                  530526e456733dff151712d1db1728cfc3bc85ed0a6c13653add2e644c57068009595b935f6a50ce4a714bad2b33bc8e
  RTMR1                  e8601b64942f9f7a66f4d8f5727c0a7d4a71953cfc3c7d13e043f8ddf4f94d2358afd17e01f567a5d8209f3cf7479489
  RTMR2                  ad1ed113dbecf8516b1ae1ba33a5188d61dd4a4baf5c181c1dd3c61ed8b91a624b5ac2242328028e540d9a2fb4f2dbfe
  RTMR3                  e1c2f169733c62b61dd28281ff8a45b8afb9f41f39ca57643b62f550382736e1e5c61f02ddc931928b0881d76b47ddc0
  report_data[..32]      fb894ba0011caafe2427f7d4ea88cd4e92ca6123e63beea9fbc2467ed8e1b232
  report_data[32..]      0000000000000000000000000000000000000000000000000000000000000000 (zero,
                         as the format requires)

── Intel collateral used ───────────────────────────────────────────────────────────────────────
  Intel-signed TCB data; altering it breaks the chain, so its source cannot change the verdict
  published by           worker.outlayer.near
  at block               209222035
  sha256                 4ce45a28f0227cf7b517151c9174f5a8a23f68cba45ef1bd942e74fc97f86bb9
  valid from             2026-07-21T00:13:24Z
  valid until            2026-08-19T23:51:19Z
  covers execution       yes — this execution falls inside the validity window
  recovered from         sync

── Checks ──────────────────────────────────────────────────────────────────────────────────────

  [ PASS     ] Authenticity  is this a genuine Intel TDX quote?
                         Intel signature chain valid, TCB UpToDate
    Intel TCB status     UpToDate

  [ PASS     ] Identity  is this code approved on chain?
                         measurements approved on worker.outlayer.near

  [ PASS     ] Binding  does the quote cover this execution?
                         report_data commits to exactly these task fields
    fields hash to       fb894ba0011caafe2427f7d4ea88cd4e92ca6123e63beea9fbc2467ed8e1b232
    quote commits to     fb894ba0011caafe2427f7d4ea88cd4e92ca6123e63beea9fbc2467ed8e1b232 —
                         identical

  PROVEN  every check passed: this input produced this output, inside genuine
          Intel TDX hardware, running code approved on chain.

  The request and response bytes were not checked — only their hashes are stored for HTTPS
  calls. Pass --input and --output, or use `outlayer-verify run`.

  Tip: --bundle proof.json saves the record, the collateral and the payloads into one file that
  re-verifies offline, years from now, with no network and no dependence on anyone still being
  around.
```

</details>

Three layers pass. The request and the response are not checked, because this was an HTTPS call and
only their hashes were ever stored — the tool says so rather than implying a completeness it does
not have. Note `secrets ref`: the execution was permitted to read one named secret profile, and that
permission is part of what the enclave signed. The secrets themselves never leave it.

**An on-chain execution, proven end to end.** Here nothing has to be kept or supplied: both payloads
live in the transaction forever.

```sh
outlayer-verify tx HBZiBDSwok8mfSpQi7cvUHvgb8GHFK8xefvj5U1k29N --network testnet
```

<details>
<summary>The whole output &mdash; all five checks, including the payload bytes</summary>

```
$ outlayer-verify tx HBZiBDSwok8mfSpQi7cvUHvgb8GHFK8xefvj5U1k29N --network testnet

▸ Fetching the record for transaction HBZiBDSwok8mfSpQi7cvUHvgb8GHFK8xefvj5U1k29N
  ✓ record found: task 2008
▸ Recovering the request and response from the chain
  ✓ both recovered from the transaction
▸ Fetching Intel collateral for platform b0c06f000000, valid at 2026-07-27T23:55:43Z
  ✓ published by worker.outlayer.testnet, valid 2026-07-21T00:13:24Z .. 2026-08-19T23:51:19Z
▸ Asking worker.outlayer.testnet whether these measurements are approved
  ✓ the chain recognises this build

── Record as published ─────────────────────────────────────────────────────────────────────────
  task id                2008
  task type              execute
  executed at            2026-07-27T23:55:43Z (1785196543)
  format                 V1 — commits to caller, project, secrets, timestamp and payment
  network                testnet
  transaction            HBZiBDSwok8mfSpQi7cvUHvgb8GHFK8xefvj5U1k29N
  block height           261245882
  caller                 maguila.testnet
  source repo            https://github.com/zavodil/weather-ark
  commit                 main
  build target           wasm32-wasip2
  wasm sha256            788e865fffddb333cf36c29b7f2251a9c3c4da8306e5527d2b1e8c7045ec4ff0
  input sha256           48592c499d13432c061534fafc8e6bd6353aeec799e6264a915805f3718344b0
  output sha256          ca6e60c897ffa2b10211bb75e5e7cfa2f8ddc0ab1727097e35b383c1ea919a29
  attached payment       0
  secrets ref            zavodil2.testnet/default

── Inside the signed quote ─────────────────────────────────────────────────────────────────────
  read from the quote AFTER Intel's signature was checked, not from the record
  size                   5006 bytes
  platform (FMSPC)       b0c06f000000 — taken from the signed PCK certificate
  MRTD                   7fe60787222bd394cb516abca2435f22f035ab2cc9c0a4b4b3b148e46297f3d931a237b72f359052c6e657d8c1409173
  RTMR0                  530526e456733dff151712d1db1728cfc3bc85ed0a6c13653add2e644c57068009595b935f6a50ce4a714bad2b33bc8e
  RTMR1                  e8601b64942f9f7a66f4d8f5727c0a7d4a71953cfc3c7d13e043f8ddf4f94d2358afd17e01f567a5d8209f3cf7479489
  RTMR2                  ad1ed113dbecf8516b1ae1ba33a5188d61dd4a4baf5c181c1dd3c61ed8b91a624b5ac2242328028e540d9a2fb4f2dbfe
  RTMR3                  655000c93bb55ab73c39472d022abbe96a46c1d4bbbb774e49ca896bfdbfb0e7fbc5422f8de3ef8c0aa060e38cf4aa6f
  report_data[..32]      1b91f4f71b77abae936bf0003fd07bf9f7d2c52195aca2f623aa2e78607eb1b1
  report_data[32..]      0000000000000000000000000000000000000000000000000000000000000000 (zero,
                         as the format requires)

── Intel collateral used ───────────────────────────────────────────────────────────────────────
  Intel-signed TCB data; altering it breaks the chain, so its source cannot change the verdict
  published by           worker.outlayer.testnet
  at block               261662085
  sha256                 4ce45a28f0227cf7b517151c9174f5a8a23f68cba45ef1bd942e74fc97f86bb9
  valid from             2026-07-21T00:13:24Z
  valid until            2026-08-19T23:51:19Z
  covers execution       yes — this execution falls inside the validity window
  recovered from         sync

── Checks ──────────────────────────────────────────────────────────────────────────────────────

  [ PASS     ] Authenticity  is this a genuine Intel TDX quote?
                         Intel signature chain valid, TCB UpToDate
    Intel TCB status     UpToDate

  [ PASS     ] Identity  is this code approved on chain?
                         measurements approved on worker.outlayer.testnet

  [ PASS     ] Binding  does the quote cover this execution?
                         report_data commits to exactly these task fields
    fields hash to       1b91f4f71b77abae936bf0003fd07bf9f7d2c52195aca2f623aa2e78607eb1b1
    quote commits to     1b91f4f71b77abae936bf0003fd07bf9f7d2c52195aca2f623aa2e78607eb1b1 —
                         identical

  [ PASS     ] Input  do the request bytes match what was attested?
                         recovered from the transaction
    content              {"city":"Buenos Aires","units":"metric"}
    hashes to            48592c499d13432c061534fafc8e6bd6353aeec799e6264a915805f3718344b0
    attested             48592c499d13432c061534fafc8e6bd6353aeec799e6264a915805f3718344b0
                         the attested value is itself inside the signed quote — it is part of
                         the commitment checked by Binding above, so matching it means matching
                         what the TEE signed

  [ PASS     ] Output  do the response bytes match what was attested?
                         recovered from the transaction
    content              {"city":"Buenos Aires","country":"AR","description":"overcast
                         clouds","humidity":89,"temperature":16.53,"temperature_unit":"C","wind_speed":1.86}
    hashes to            ca6e60c897ffa2b10211bb75e5e7cfa2f8ddc0ab1727097e35b383c1ea919a29
    attested             ca6e60c897ffa2b10211bb75e5e7cfa2f8ddc0ab1727097e35b383c1ea919a29
                         the attested value is itself inside the signed quote — it is part of
                         the commitment checked by Binding above, so matching it means matching
                         what the TEE signed

  PROVEN  every check passed: this input produced this output, inside genuine
          Intel TDX hardware, running code approved on chain.

  Tip: --bundle proof.json saves the record, the collateral and the payloads into one file that
  re-verifies offline, years from now, with no network and no dependence on anyone still being
  around.
```

</details>

Here all five checks run: the request and the response come out of the transaction itself, so the
bytes are compared, not just the hashes the quote commits to.

**An HTTPS call, made and proven in one step.** This is a real mainnet call to the price oracle
above. Reproducing it needs a payment key of your own — the execution is paid for — which is exactly
the point: you do not have to trust the output below, you can produce your own.

`run` makes the call and keeps both payloads. That matters because only their hashes are stored
server-side, so this is the only moment the request and the response exist anywhere else.
`--secrets-ref` names the secret profile the program is allowed to read; it is part of the attested
commitment, so the proof records what the execution was permitted to touch. The secrets themselves
never leave the enclave.

```sh
outlayer-verify run price-oracle.near/price-oracle --network mainnet \
  --input '{"command":"get_signed_prices","tokens":["wrap.near","nbtc.bridge.near","eth.bridge.near"],"max_age_secs":30,"exclude_sources":["pyth","chainlink"]}' \
  --secrets-ref price-oracle.near/oracle \
  --payment-key "$KEY"
```

<details>
<summary>The whole output &mdash; all five checks on a live mainnet execution</summary>

```
▸ Calling price-oracle.near/price-oracle on mainnet
  ✓ call be63e017-3feb-4f16-96d2-b2a6114b1152 — completed
  ✓ request and response captured — they cannot be recovered later
▸ Waiting for the worker to publish the attestation
  ✓ attestation published: task 221314
▸ Fetching Intel collateral for platform b0c06f000000, valid at 2026-07-31T10:03:12Z
  ✓ published by worker.outlayer.near, valid 2026-07-21T00:13:24Z .. 2026-08-19T23:51:19Z
▸ Asking worker.outlayer.near whether these measurements are approved
  ✓ the chain recognises this build

── Record as published ─────────────────────────────────────────────────────────────────────────
  task id                221314
  task type              execute
  executed at            2026-07-31T10:03:12Z (1785492192)
  format                 V1 — commits to caller, project, secrets, timestamp and payment
  network                mainnet
  call id                be63e017-3feb-4f16-96d2-b2a6114b1152
  caller                 price-oracle.near
  project                price-oracle.near/price-oracle
  build target           wasm32-wasip2
  wasm sha256            3ff2c6fb9241ad4f5a3a40298b78d68b4da31b6760ecea3d5253579ec33809e7
  input sha256           3111dc537f79650f8a00524e0a31f12b72c428284f3cb4260cde3f3e9e9905dd
  output sha256          ac8f86b931daf2bd4461fd54db75cd09fcbf32a45927bb2fea34cc43920d33f8
  attached payment       0
  secrets ref            price-oracle.near/oracle

── Inside the signed quote ─────────────────────────────────────────────────────────────────────
  read from the quote AFTER Intel's signature was checked, not from the record
  size                   5006 bytes
  platform (FMSPC)       b0c06f000000 — taken from the signed PCK certificate
  MRTD                   7fe60787222bd394cb516abca2435f22f035ab2cc9c0a4b4b3b148e46297f3d931a237b72f359052c6e657d8c1409173
  RTMR0                  530526e456733dff151712d1db1728cfc3bc85ed0a6c13653add2e644c57068009595b935f6a50ce4a714bad2b33bc8e
  RTMR1                  e8601b64942f9f7a66f4d8f5727c0a7d4a71953cfc3c7d13e043f8ddf4f94d2358afd17e01f567a5d8209f3cf7479489
  RTMR2                  ad1ed113dbecf8516b1ae1ba33a5188d61dd4a4baf5c181c1dd3c61ed8b91a624b5ac2242328028e540d9a2fb4f2dbfe
  RTMR3                  001f49dde2ea600119c298ca92212f044d220bedaf067ee5cc817103350d201538224a0880014830ca3d988b7f159b75
  report_data[..32]      9c6008f3ce30b5469f688e0f6fbf153e128d738f386879594b8ba709928a80f3
  report_data[32..]      0000000000000000000000000000000000000000000000000000000000000000 (zero,
                         as the format requires)

── Intel collateral used ───────────────────────────────────────────────────────────────────────
  Intel-signed TCB data; altering it breaks the chain, so its source cannot change the verdict
  published by           worker.outlayer.near
  at block               209222035
  sha256                 4ce45a28f0227cf7b517151c9174f5a8a23f68cba45ef1bd942e74fc97f86bb9
  valid from             2026-07-21T00:13:24Z
  valid until            2026-08-19T23:51:19Z
  covers execution       yes — this execution falls inside the validity window
  recovered from         sync

── Checks ──────────────────────────────────────────────────────────────────────────────────────

  [ PASS     ] Authenticity  is this a genuine Intel TDX quote?
                         Intel signature chain valid, TCB UpToDate
    Intel TCB status     UpToDate

  [ PASS     ] Identity  is this code approved on chain?
                         measurements approved on worker.outlayer.near

  [ PASS     ] Binding  does the quote cover this execution?
                         report_data commits to exactly these task fields
    fields hash to       9c6008f3ce30b5469f688e0f6fbf153e128d738f386879594b8ba709928a80f3
    quote commits to     9c6008f3ce30b5469f688e0f6fbf153e128d738f386879594b8ba709928a80f3 —
                         identical

  [ PASS     ] Input  do the request bytes match what was attested?
                         the request you supplied
    content              {"command":"get_signed_prices","tokens":["wrap.near","nbtc.bridge.near","eth.bridge.near"],"max_age_secs":30,"exclude_sources":["pyth","chainlink"]}
    hashes to            3111dc537f79650f8a00524e0a31f12b72c428284f3cb4260cde3f3e9e9905dd
    attested             3111dc537f79650f8a00524e0a31f12b72c428284f3cb4260cde3f3e9e9905dd
                         the attested value is itself inside the signed quote — it is part
                         of the commitment checked by Binding above, so matching it means
                         matching what the TEE signed

  [ PASS     ] Output  do the response bytes match what was attested?
                         the response you supplied
    content              {"error":null,"payload":"{\"eth.bridge.near\":{\"price\":\"188246333333\",\"expo\":-8,\"publish_time\":1785492182},\"nbtc.bridge.near\":{\"price\":\"6367973333333\",\"expo\":-8,\"publish_time\":1785492182},\"wrap.near\":{\"price\":\"163883333\",\"expo\":-8,\"publish_time\":1785492182}}","public_key":"ed25519:FU6EnB4UaAiDCAxvQPkRUu5QQExgzvKQAX891wMEX3rU","sig_format":"json","signature":"hQHOc3RRkN9DzRjXXCsAFA5DxjAlA+bRjtrfZHbJk+5wQ4wA13ZilFADlQTIUr2nGK+5WvrjT8F7i1wBaRsTAg==","success":true}
    hashes to            ac8f86b931daf2bd4461fd54db75cd09fcbf32a45927bb2fea34cc43920d33f8
    attested             ac8f86b931daf2bd4461fd54db75cd09fcbf32a45927bb2fea34cc43920d33f8
                         the attested value is itself inside the signed quote — it is part
                         of the commitment checked by Binding above, so matching it means
                         matching what the TEE signed

  PROVEN  every check passed: this input produced this output, inside genuine
          Intel TDX hardware, running code approved on chain.
```

</details>

Note the last two checks. The oracle returned signed prices, and the tool confirms that the exact
response you received — signature and all — is the one the enclave committed to before Intel signed
the quote. A response altered anywhere between the enclave and your process would fail here.

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

### Payloads

For an **on-chain** execution there is nothing to keep: the request is in the contract's
`execution_requested` event and the response is the value the contract returned, both permanently in
the transaction. `outlayer-verify tx` reads them from an archival node and checks the bytes for you.

For an **HTTPS** call only the hashes are ever stored. If you did not keep the request and the
response, that execution can never be fully verified again — by anyone, including the operator. This
is why `run` exists: it performs the call and keeps both payloads, so the proof is possible at all.
If you call the API yourself, save what you sent and what you got back, and pass them later:

```sh
# run it through the tool — payloads captured automatically
outlayer-verify run alice.testnet/my-agent --network testnet \
  --input request.json --payment-key 'alice.testnet:4:<key>'

# or verify a call you made yourself, with the payloads you kept
outlayer-verify call c231b0f6-78d7-48f4-9c23-458b4081d84f --network testnet \
  --input request.json --output response.json
```

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

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option — the Rust
ecosystem default, and deliberately the least restrictive thing we could pick. A tool whose purpose
is letting you check us should not come with terms worth thinking about before you run it in your
own pipeline.
