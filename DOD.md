# Definition of Done — aiolic

The six required items, each with the evidence rather than the assertion.

## 1. PLAN.md with failure conditions written before the code

`PLAN.md` exists and states the reversed contract, what the project is, and six
failure conditions written before any code:

1. A signature that does not verify against its own public key.
2. An HMAC that does not cover the fields it claims to.
3. An Ed25519 signature over the wrong message.
4. A gate that accepts an unregistered device.
5. A job grant that ignores `job_hash`.
6. Replay accepted.

It also states, up front, what the project does **not** claim: a stock client
will not accept these responses, because the vendor's private key is not known.

## 2. RESEARCH.md — the reversed contract

The research for this project is the reversing done in the companion repository
(`~/aio-mod-re/FINDINGS.md`, `WALKTHROUGH.md`, 2026-10-09), which is where the
protocol came from. Rather than restate it, this repository records what was
**measured here** to select and justify the target:

- The ecosystem check: a search for an implementation of this protocol returns
  nothing. What exists is `fakelicstls.py` (a canned-response fake server) and
  client-side hooks — the bypass, not a server.
- The gap that defines the project: the findings record that **eleven response
  schemes were brute-forced against the fake server and all failed**, and that
  the second and third gates had to be defeated in the client instead. That is
  the measurement showing the response signing was never implemented.
- The decision to reimplement rather than extend the bypass: extending it would
  repeat work already done (PLAN notes this explicitly).

**Honest note on scope:** this repository does not contain a from-scratch
protocol investigation, because the protocol was already investigated. What it
contains is the implementation that investigation implied and never produced.
Saying so is better than presenting the companion research as new.

## 3. Working code

890 lines of non-test Go, standard library only. One binary with three
subcommands (`serve`, `verify`, `genkey`), one internal package holding the gates
and the signing, one holding the HTTP surface and the verifiers.

Mechanisms are real, not sketched:

- **Ed25519** (`crypto/ed25519`) for `ed25519_sig`, over a canonical field
  encoding that sorts field names and joins them as `name=value` lines.
- **HMAC-SHA256** (`crypto/hmac`) for `sig`, over the same bytes.
- **The device registry**, with entitlement decided by both a registration check
  and an expiry check, which are separate conditions.
- **The job registry**, mapping feature to hash, so `job_hash` is cross-checked
  against the artifact it belongs to.
- **Nonce replay prevention**, with the nonce released when a request turns out
  invalid so a failed attempt does not burn it.
- **A real HTTP server** with the nine endpoints the client calls.

## 4. Tests, actually executed

```
$ go test ./internal/... -v
14 top-level tests, 23 including subtests
TEST_EXIT=0
RACE_EXIT=0
VET_EXIT=0
GOFMT clean
```

**6 of 6 planted mutations were caught.** Each mutation targets a specific gate
and the suite failed on every one:

| mutation | result |
| --- | --- |
| HMAC signs a constant instead of the message | caught |
| unregistered device treated as VIP | caught |
| `job_hash` comparison removed | caught |
| nonce replay prevention removed | caught |
| expiry check removed (`vip := dev.VIP`) | caught |
| canonical encoding truncated to one field | caught |

**The first mutation initially survived**, and that is worth recording: making the
HMAC a constant still passed, because `VerifyDeviceCheck` called the same
`hmacHex` helper the signer did, so a broken helper verified its own output. The
fix was a test that recomputes the HMAC itself with its own `hmac.New` call and
its own canonical message, and asserts that two different field sets produce two
different digests. Re-running the mutation then failed the suite, as it must.

A test that cannot fail is decoration; this one could not fail until it was
rewritten, and the mutation is what revealed it.

## 5. Honest README

`README.md` states the protocol, the signing scheme, how to run it, and a
"Limitations, stated honestly" section listing four things that are not done:

- `X-Req-Sig` (the request signature) is not verified, because its derivation was
  not recovered; the server checks the client key and the nonce and says so.
- The layer-three response bodies are shaped from the findings, not a capture.
- The client's public key is unknown, so responses cannot be accepted by a stock
  client and the TLS pin cannot be satisfied.
- No TLS certificate is shipped for the pin.

It also states plainly, twice, that this is not a working bypass of the stock
client — which is the claim a reader would otherwise assume.

## 6. Commit

One commit, short message, on `main`, pushed to the project's own repository.

## Evidence of the end-to-end path

`run.sh` starts the server, makes real requests, and verifies real responses:

```
== end-to-end: server, request, verify, tamper ==
device check: status=200
job claim:    status=200

verify device check: device-check: valid (hwid=AIO3-… vip=true expires=2027-01-01)
verify job claim:    job-claim: valid (feature=SSL_PINNING_BYPASS granted=true)

now altering a signed field in each response:
device-check: INVALID — ed25519 signature does not verify
tampered device check: device-check: INVALID — ed25519 signature does not verify
rejected, as it must be
```

`RUNSH_EXIT=0`. The recorded responses from that run are committed under
`testdata/`.

## What is not done, restated

- A stock AIO-MOD client will not accept this server. The vendor's private key is
  not known and the client pins its certificate.
- The `X-Req-Sig` request signature is unverified; its construction was not
  recovered.
- Layer-three response bodies follow the documented envelope, not an observed one.
