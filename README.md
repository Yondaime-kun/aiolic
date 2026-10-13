# aiolic

A license server that speaks the reversed **AIO-MOD Toolkit** protocol.

AIO-MOD is a paid Android/Linux tool whose entitlement is decided entirely by a
server over HTTPS. Its protocol was reversed from the client and the findings are
in a companion repository. What came out of that work was a *bypass*: a fake
server returning a canned response, plus client-side patches that stub out the
verifier so the canned response is accepted.

That bypass proves the protocol is understood well enough to lie to one build. It
does not implement it — the response signing was never done, which is why the
client had to be patched at all. Eleven response schemes were tried against the
fake server and all of them failed, so the layered gates were defeated *in the
client* instead.

**This is the server that was never written.** It answers the client's endpoints
and signs its responses the way the client expects, so the thing the bypass
worked around is actually implemented.

```
 $ aiolic serve -addr :8443 -tls-cert cert.pem -tls-key key.pem -devices devices.json
 $ curl -sXPOST localhost:8443/v1/device/check -d '{"app_version":"aio-mod","hwid":"AIO3-…"}'
 {"ok":true,"is_vip":true,"expires_at":"2027-01-01","sig_alg":"Ed25519", …,
  "ed25519_sig":"RGzg1a0AzeD…","sig":"318f56fbefe7…"}

 $ aiolic verify -response device.json -pub <hex> -hmac <hex>
 device-check: valid (hwid=AIO3-… vip=true expires=2027-01-01)
```

## What it implements

Three gates, all from the reversed contract:

**`POST /v1/device/check`** — entitlement. Takes the client's `app_version` and
`hwid`, checks the device is registered and not expired, and answers with the
VIP body including both signature fields.

**`POST /v1/job/claim`** — the per-tool grant. Takes `feature`, `hwid`,
`job_hash` and `request_id`. The `job_hash` is constant per APK, so the server
holds the feature-to-hash mapping and refuses a claim whose hash does not match
the one registered — that cross-check is the reason the field is in the request.

**The layer-three endpoints** — `/v1/smart/token`, `/v1/special/claim`,
`/v1/usage/check`, `/v1/usage/mark`, `/v1/free/verify`,
`/v1/compiler/bootstrap`, `/v1/compiler/assertion`. These answer with a signed
envelope. Their field-by-field response shape was not recovered from the client,
so they return the fields the findings document and a real signature, rather than
a structure invented to look complete.

## The signing

Two signatures on every response, matching what the client was observed to check:

- **`ed25519_sig`** — Ed25519 over a canonical encoding of the response's signed
  fields, tagged `sig_alg: "Ed25519"` and `sig_kid: "aio-license-2026-01"`.
- **`sig`** — an HMAC-SHA256 over the same canonical bytes, hex encoded.

The canonical form sorts the field names and joins them as `name=value` lines.
The signer and the verifier share that one function, deliberately: a signature is
only meaningful if both sides agree on exactly what is covered, and sharing the
encoder is what keeps the two from drifting apart.

## Verification, and what it proves

`aiolic verify` recomputes both signatures on a recorded response and reports
whether they hold. It is not a courtesy check — it is the thing the original
bypass never had:

```
$ aiolic verify -response sample_device_check.json -pub <pub> -hmac <key>
device-check: valid (hwid=AIO3-… vip=true expires=2027-01-01)
$ # change is_vip to false, or expires_at to 2099, or granted to false
device-check: INVALID — ed25519 signature does not verify
```

Every signed field, once altered, breaks the signature. That is asserted per field
in the test suite, so a field that silently stops being covered fails the build.

## What this does not claim

**A stock client will not accept this server.** The client verifies signatures
with a public key embedded in it, and producing a signature that key accepts
requires the matching **private** key, which belongs to the vendor and is not in
the findings. The client also pins a certificate.

So the claim is precise: **the protocol is implemented correctly and its
cryptography is verifiable**, against the server's own advertised key. The
difference between "the protocol is implemented" and "the vendor's key is known"
is the difference between this project and the bypass it grew out of, and it is
stated here rather than left to be discovered.

## Build and run

```
go build ./cmd/aiolic            # or: ./run.sh
./run.sh                         # build, vet, test, then a live end-to-end demo
```

The demo starts the server on a loopback port, makes a real device check and a
real job claim, verifies both with the CLI, then alters a field in each and shows
the verifier rejecting them.

## Layout

```
cmd/aiolic/main.go              serve, verify and genkey
internal/aiolic/server.go       the gates, the device registry, the signing
internal/aiolic/http.go         the HTTP surface and the verifiers
internal/aiolic/server_test.go  the suite, including the per-field mutation checks
testdata/                       a recorded device check and job claim
```

## Limitations, stated honestly

- **The `X-Req-Sig` request signature is not verified.** The client sends
  `X-Client-Key`, `X-Req-Time`, `X-Req-Nonce` and `X-Req-Sig`; the formula that
  builds `X-Req-Sig` was not recovered, so the server checks the client key and
  the nonce and does not pretend to check a signature whose derivation is
  unknown. `ValidateAuth` says so in its comment.
- **The layer-three responses are shaped from the findings, not from a capture.**
  Only the device-check and job-claim bodies were recovered field by field.
- **The client's public key is not known**, so responses cannot be verified by the
  client and the TLS pin cannot be satisfied. See the section above.
- **No TLS termination is included for a pinned certificate.** `serve` accepts a
  certificate so the pin can be exercised, but it does not ship one.
