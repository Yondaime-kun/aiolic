# aiolic — plan

## Where this comes from

Not a patcher, and not a client-side hook. This is the other half.

`AIO-MOD Toolkit v3.5.2` is a paid Android/Linux tool whose entitlement is decided
entirely by a license server over HTTPS. Its protocol was reversed on 2026-10-09
and the findings are recorded in `~/aio-mod-re/FINDINGS.md` and `WALKTHROUGH.md`.
What exists from that work is a *bypass*: a fake TLS server that returns a
canned VIP body, plus client-side monkeypatches that stub out the verifier and
seven engine functions. Both are tricks played on a client that was already
broken open.

That is not an implementation. It proves the protocol is understood well enough
to lie to one specific build, but the response signing was never done — the
brute force of eleven response schemes against the fake server **failed**, which
is why the layered gates had to be defeated client-side instead.

This project is the server that was never written: a license server that speaks
the reversed protocol **correctly**, signing its responses the way the engine
expects, so that a *stock* engine accepts it. The reversed contract is the
specification. The code is new.

## The reversed contract

From the findings, all of it measured rather than assumed:

### Transport

TLS, with certificate pinning on the client side — the pin is why the bypass had
to ship a CA and a leaf certificate rather than plain HTTP.

### `POST /v1/device/check` — entitlement

Request body:
```json
{"app_version": "aio-mod", "hwid": "AIO3-<64 lowercase hex>"}
```
Request headers:
```
X-Client-Key: <client key>
X-Req-Time:   <time>
X-Req-Nonce:  <32 hex>
X-Req-Sig:    <64 hex>
User-Agent:   AIO-Mod/1.0
```
Response, 509 bytes, with these fields:
```json
{
  "ok": true,
  "hwid": "...", "registered_at": "...",
  "is_vip": true, "expires_at": "2069-06-09", "server_time": ...,
  "nonce": "...", "req_nonce": "...",
  "sig_alg": "Ed25519", "sig_kid": "aio-license-2026-01",
  "ed25519_sig": "...", "sig": "<hmac>"
}
```

### `POST /v1/job/claim` — per-tool grant

Request, 253 bytes:
```json
{"feature": "SSL_PINNING_BYPASS", "hwid": "AIO3-<64 hex>",
 "job_hash": "<64 hex>", "request_id": "<48 hex>"}
```
- `job_hash` is constant per APK (a hash of the APK), so the server can cross-check
  what is being claimed.
- `request_id` is fresh per request.
- The response **must carry a valid `sig`**. A missing signature produces
  "Tanda tangan respons server tidak valid"; a valid signature with missing
  fields produces "Server menolak claim". Eleven response schemes were tried
  against the fake server and all failed.

### Layer three — the rest of the surface

`/v1/smart/token`, `/v1/special/claim`, `/v1/usage/check`, `/v1/usage/mark`,
`/v1/free/verify`, `/v1/compiler/bootstrap`, `/v1/compiler/assertion`.

The engine names these in its own decrypted memory (`_aio_smart_build_token`,
`_aio_special_claim_apk`, `_aio_server_usage_check`, `_aio_server_usage_mark`,
`_require_vip_feature`).

### Signing

`ed25519_sig` with `sig_kid` `aio-license-2026-01`, plus a separate `sig` that is
an HMAC over the response body. The engine is *fail-closed*: no signature, or a
signature it cannot verify, means no entitlement.

**Two things about which the findings are explicit and this project must respect:
the signature scheme is Ed25519 (not something else that happens to verify), and
the response signature is what makes or breaks a claim.**

## What it will be

A single Go binary serving the reversed API over TLS, with:

1. **The device gate** — parses the HWID, decides entitlement, and signs the
   response with Ed25519 plus the HMAC.
2. **The job gate** — validates `feature` and `job_hash`, enforces the per-APK
   rule, and returns a signed grant.
3. **The remaining endpoints** — token, usage and quota, each returning what the
   engine's decoder expects.
4. **A self-check** — the server signs its own responses and verifies them with
   the public key it advertises, so a signature bug cannot ship silently.

Plus the thing that makes the whole exercise checkable: an **offline verification
harness** that recomputes the HMAC and the Ed25519 signature over a recorded
response exactly the way the engine would, and reports whether it holds.

## Failure conditions

Written before the code.

1. **A signature that does not verify against its own public key.** Every response
   the server emits must be verified by the included checker. A server that signs
   and cannot be checked is the same as no signature, and this is the specific
   thing the original bypass got wrong.

2. **An HMAC that does not cover the fields it claims to.** Changing any signed
   field in a recorded response must make the checker fail. If a field can be
   edited without invalidating the signature, the signature does not cover it.

3. **An Ed25519 signature over the wrong message.** The message the engine signs
   over is not necessarily the whole body; if a test cannot distinguish a
   signature over the body from one over a wrong-but-similar string, the scheme is
   not implemented.

4. **A gate that accepts an unregistered device.** A HWID the server has never
   seen must not receive `is_vip: true`.

5. **A job grant that ignores `job_hash`.** Two different APKs claiming the same
   feature must be distinguishable; a grant that fires regardless of `job_hash`
   has lost the cross-check the findings call out.

6. **Replay accepted.** The request carries a nonce and the response echoes it. A
   recorded request replayed unchanged must not produce a fresh valid grant.

## What is not claimed

The engine verifies signatures with a public key embedded in the client. A server
cannot produce a signature that a *stock* client accepts unless it holds the
corresponding **private** key — which belongs to the vendor and is not in the
findings. So this project does not claim "a stock engine now works": it claims
**the protocol is implemented correctly and its cryptography is verifiable**, and
the harness proves the signatures hold against the server's own advertised key.

That distinction is stated here rather than buried, because the difference
between "the protocol is implemented" and "the vendor's key is known" is exactly
the difference between this project and the bypass it grew out of.
