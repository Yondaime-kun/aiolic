package aiolic

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func newTestServer(t *testing.T) (*Server, *Handler) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	_ = pub
	key := bytes.Repeat([]byte{0x5a}, 32)
	s := New(priv, key, "client-key-abc")
	return s, NewHandler(s)
}

const (
	testHWID = "AIO3-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testJob  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	otherJob = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	reqNonce = "0102030405060708090a0b0c0d0e0f10"
)

func auth() RequestAuth {
	return RequestAuth{
		ClientKey: "client-key-abc",
		ReqTime:   "1700000000",
		ReqNonce:  reqNonce,
		ReqSig:    strings.Repeat("ab", 32),
		UserAgent: UserAgent,
	}
}

func authWithNonce(n string) RequestAuth {
	a := auth()
	a.ReqNonce = n
	return a
}

// registerVIP registers a device entitled for a year.
func registerVIP(t *testing.T, s *Server) {
	t.Helper()
	err := s.Register(Device{
		HWID:         testHWID,
		RegisteredAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		VIP:          true,
		ExpiresAt:    time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		Jobs:         map[string]string{"SSL_PINNING_BYPASS": testJob},
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
}

// TestSignatureVerifies is failure condition 1: every response the server emits
// must verify against the public key it advertises.
func TestSignatureVerifies(t *testing.T) {
	s, h := newTestServer(t)
	registerVIP(t, s)

	resp, err := s.DeviceCheck(DeviceCheckRequest{AppVersion: "aio-mod", HWID: testHWID}, auth())
	if err != nil {
		t.Fatalf("device check: %v", err)
	}
	if !resp.OK || !resp.IsVIP {
		t.Fatalf("expected a VIP response, got %+v", resp)
	}
	if err := VerifyDeviceCheck(&resp, h.Pub, s.HMACKey); err != nil {
		t.Fatalf("response signature does not verify: %v", err)
	}

	claim, err := s.JobClaim(JobClaimRequest{
		Feature: "SSL_PINNING_BYPASS", HWID: testHWID, JobHash: testJob,
		RequestID: strings.Repeat("cd", 24),
	}, authWithNonce("11111111111111111111111111111111"))
	if err != nil {
		t.Fatalf("job claim: %v", err)
	}
	if !claim.Granted {
		t.Fatalf("expected a grant, got %+v", claim)
	}
	if err := VerifyJobClaim(&claim, h.Pub, s.HMACKey); err != nil {
		t.Fatalf("claim signature does not verify: %v", err)
	}
}

// TestTamperedFieldBreaksSignature is failure condition 2: a signed field, once
// altered, must invalidate the signature. If any field can be changed without
// breaking it, that field is not covered.
func TestTamperedFieldBreaksSignature(t *testing.T) {
	s, h := newTestServer(t)
	registerVIP(t, s)

	resp, err := s.DeviceCheck(DeviceCheckRequest{AppVersion: "aio-mod", HWID: testHWID}, auth())
	if err != nil {
		t.Fatalf("device check: %v", err)
	}
	if err := VerifyDeviceCheck(&resp, h.Pub, s.HMACKey); err != nil {
		t.Fatalf("baseline must verify: %v", err)
	}

	// Each mutation must break it. A field that is not covered is a gap.
	mutations := []struct {
		name string
		do   func(r *DeviceCheckResponse)
	}{
		{"expires_at", func(r *DeviceCheckResponse) { r.ExpiresAt = "2099-01-01" }},
		{"is_vip", func(r *DeviceCheckResponse) { r.IsVIP = false }},
		{"nonce", func(r *DeviceCheckResponse) { r.Nonce = strings.Repeat("00", 16) }},
		{"hwid", func(r *DeviceCheckResponse) { r.HWID = "AIO3-" + strings.Repeat("1", 64) }},
		{"server_time", func(r *DeviceCheckResponse) { r.ServerTime++ }},
		{"registered_at", func(r *DeviceCheckResponse) { r.RegisteredAt = "1999-01-01" }},
	}
	for _, m := range mutations {
		t.Run(m.name, func(t *testing.T) {
			cp := resp
			m.do(&cp)
			if err := VerifyDeviceCheck(&cp, h.Pub, s.HMACKey); err == nil {
				t.Errorf("changing %s did not break the signature: it is not covered", m.name)
			}
		})
	}

	// Same for the claim.
	claim, err := s.JobClaim(JobClaimRequest{
		Feature: "SSL_PINNING_BYPASS", HWID: testHWID, JobHash: testJob,
		RequestID: strings.Repeat("cd", 24),
	}, authWithNonce("22222222222222222222222222222222"))
	if err != nil {
		t.Fatalf("job claim: %v", err)
	}
	for _, m := range []struct {
		name string
		do   func(r *JobClaimResponse)
	}{
		{"feature", func(r *JobClaimResponse) { r.Feature = "OTHER" }},
		{"job_hash", func(r *JobClaimResponse) { r.JobHash = otherJob }},
		{"granted", func(r *JobClaimResponse) { r.Granted = false }},
	} {
		t.Run("claim_"+m.name, func(t *testing.T) {
			cp := claim
			m.do(&cp)
			if err := VerifyJobClaim(&cp, h.Pub, s.HMACKey); err == nil {
				t.Errorf("changing %s did not break the claim signature", m.name)
			}
		})
	}
}

// TestSignatureOverWrongMessageIsRejected is failure condition 3: a signature
// computed over a different message must not verify. This checks the verifier is
// actually binding the message and not just the presence of 64 bytes.
func TestSignatureOverWrongMessageIsRejected(t *testing.T) {
	s, h := newTestServer(t)
	registerVIP(t, s)

	resp, err := s.DeviceCheck(DeviceCheckRequest{AppVersion: "aio-mod", HWID: testHWID}, auth())
	if err != nil {
		t.Fatalf("device check: %v", err)
	}
	// Sign an unrelated message with the same key and plant it.
	bad := ed25519.Sign(s.EdPriv, []byte("a completely different message"))
	resp.Ed25519Sig = hex.EncodeToString(bad)
	if err := VerifyDeviceCheck(&resp, h.Pub, s.HMACKey); err == nil {
		t.Fatal("a signature over an unrelated message was accepted")
	}

	// And a well-formed signature from a different key.
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	resp2 := resp
	resp2.Ed25519Sig = encodeB64(ed25519.Sign(otherPriv, canonical(deviceCheckFields(&resp))))
	if err := VerifyDeviceCheck(&resp2, h.Pub, s.HMACKey); err == nil {
		t.Fatal("a signature from an unrelated key was accepted")
	}
}

// TestUnregisteredDeviceIsNotVIP is failure condition 4.
func TestUnregisteredDeviceIsNotVIP(t *testing.T) {
	s, _ := newTestServer(t)
	unknown := "AIO3-" + strings.Repeat("ff", 32)

	_, err := s.DeviceCheck(DeviceCheckRequest{AppVersion: "aio-mod", HWID: unknown}, auth())
	if !errors.Is(err, ErrUnknown) {
		t.Fatalf("unregistered device: err = %v, want ErrUnknown", err)
	}
	// And the nonce must not have been burned by the failed attempt.
	if _, err := s.DeviceCheck(DeviceCheckRequest{AppVersion: "aio-mod", HWID: testHWID}, auth()); errors.Is(err, ErrReplay) {
		t.Fatal("a failed request consumed the nonce")
	}
}

// TestJobHashIsEnforced is failure condition 5: the job hash ties a claim to a
// specific artifact, so a mismatched hash must be refused.
func TestJobHashIsEnforced(t *testing.T) {
	s, _ := newTestServer(t)
	registerVIP(t, s)

	_, err := s.JobClaim(JobClaimRequest{
		Feature: "SSL_PINNING_BYPASS", HWID: testHWID, JobHash: otherJob,
		RequestID: strings.Repeat("cd", 24),
	}, authWithNonce("33333333333333333333333333333333"))
	if !errors.Is(err, ErrJobHash) {
		t.Fatalf("wrong job hash: err = %v, want ErrJobHash", err)
	}

	// The right hash still works, so the check is not simply always failing.
	_, err = s.JobClaim(JobClaimRequest{
		Feature: "SSL_PINNING_BYPASS", HWID: testHWID, JobHash: testJob,
		RequestID: strings.Repeat("cd", 24),
	}, authWithNonce("44444444444444444444444444444444"))
	if err != nil {
		t.Fatalf("correct job hash was refused: %v", err)
	}

	// An unknown feature is refused too.
	_, err = s.JobClaim(JobClaimRequest{
		Feature: "NOT_A_FEATURE", HWID: testHWID, JobHash: testJob,
		RequestID: strings.Repeat("cd", 24),
	}, authWithNonce("55555555555555555555555555555555"))
	if !errors.Is(err, ErrUnknownFeat) {
		t.Fatalf("unknown feature: err = %v, want ErrUnknownFeat", err)
	}
}

// TestReplayIsRefused is failure condition 6.
func TestReplayIsRefused(t *testing.T) {
	s, _ := newTestServer(t)
	registerVIP(t, s)

	a := authWithNonce("66666666666666666666666666666666")
	if _, err := s.DeviceCheck(DeviceCheckRequest{AppVersion: "aio-mod", HWID: testHWID}, a); err != nil {
		t.Fatalf("first request: %v", err)
	}
	if _, err := s.DeviceCheck(DeviceCheckRequest{AppVersion: "aio-mod", HWID: testHWID}, a); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay: err = %v, want ErrReplay", err)
	}
}

// TestExpiredEntitlementIsRefused checks the time gate, which is separate from
// the registration gate.
func TestExpiredEntitlementIsRefused(t *testing.T) {
	s, _ := newTestServer(t)
	if err := s.Register(Device{
		HWID:         testHWID,
		RegisteredAt: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		VIP:          true,
		ExpiresAt:    time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
		Jobs:         map[string]string{},
	}); err != nil {
		t.Fatalf("register: %v", err)
	}
	_, err := s.DeviceCheck(DeviceCheckRequest{AppVersion: "aio-mod", HWID: testHWID}, auth())
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: err = %v, want ErrExpired", err)
	}
}

// TestBadClientKeyIsRefused checks that the client key is actually compared.
func TestBadClientKeyIsRefused(t *testing.T) {
	s, _ := newTestServer(t)
	registerVIP(t, s)

	a := auth()
	a.ClientKey = "wrong"
	if _, err := s.DeviceCheck(DeviceCheckRequest{AppVersion: "aio-mod", HWID: testHWID}, a); !errors.Is(err, ErrSignature) {
		t.Fatalf("wrong client key: err = %v, want ErrSignature", err)
	}
}

// TestMalformedNonceIsRefused checks that a missing or non-hex nonce is caught
// before it reaches the replay table.
func TestMalformedNonceIsRefused(t *testing.T) {
	s, _ := newTestServer(t)
	registerVIP(t, s)
	for _, n := range []string{"", "short", strings.Repeat("zz", 16), strings.Repeat("ab", 15)} {
		a := authWithNonce(n)
		if _, err := s.DeviceCheck(DeviceCheckRequest{AppVersion: "aio-mod", HWID: testHWID}, a); !errors.Is(err, ErrBadNonce) {
			t.Errorf("nonce %q: err = %v, want ErrBadNonce", n, err)
		}
	}
}

// TestHWIDValidation checks the documented shape.
func TestHWIDValidation(t *testing.T) {
	good := []string{
		testHWID,
		"AIO3-" + strings.Repeat("0", 64),
	}
	bad := []string{
		"",
		"AIO3-",
		"AIO3-" + strings.Repeat("0", 63),
		"AIO3-" + strings.Repeat("0", 65),
		"AIO3-" + strings.Repeat("Z", 64),
		"aio3-" + strings.Repeat("0", 64),
		strings.Repeat("0", 64),
	}
	for _, g := range good {
		if !ValidHWID(g) {
			t.Errorf("ValidHWID(%q) = false, want true", g)
		}
	}
	for _, b := range bad {
		if ValidHWID(b) {
			t.Errorf("ValidHWID(%q) = true, want false", b)
		}
	}
}

// TestHTTPEndpoints exercises the wire path, including that the JSON the client
// receives decodes and carries a verifiable signature.
func TestHTTPEndpoints(t *testing.T) {
	s, h := newTestServer(t)
	registerVIP(t, s)
	srv := httptest.NewServer(h.Routes())
	defer srv.Close()

	body, _ := json.Marshal(DeviceCheckRequest{AppVersion: "aio-mod", HWID: testHWID})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/device/check", bytes.NewReader(body))
	req.Header.Set("X-Client-Key", "client-key-abc")
	req.Header.Set("X-Req-Nonce", "77777777777777777777777777777777")
	req.Header.Set("User-Agent", UserAgent)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", res.StatusCode)
	}
	var got DeviceCheckResponse
	if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if err := VerifyDeviceCheck(&got, h.Pub, s.HMACKey); err != nil {
		t.Fatalf("wire response does not verify: %v", err)
	}

	// A layer-three endpoint answers with a real signature too.
	req2, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/usage/check", bytes.NewReader([]byte("{}")))
	req2.Header.Set("X-Client-Key", "client-key-abc")
	req2.Header.Set("X-Req-Nonce", "88888888888888888888888888888888")
	res2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer res2.Body.Close()
	var env map[string]any
	if err := json.NewDecoder(res2.Body).Decode(&env); err != nil {
		t.Fatalf("decode env: %v", err)
	}
	if err := VerifyGeneric(env, h.Pub, s.HMACKey); err != nil {
		t.Fatalf("generic response does not verify: %v", err)
	}
}

// TestUnknownDeviceOverHTTPIsForbidden checks the wire-level status for a refusal.
func TestUnknownDeviceOverHTTPIsForbidden(t *testing.T) {
	s, h := newTestServer(t)
	_ = s
	srv := httptest.NewServer(h.Routes())
	defer srv.Close()

	body, _ := json.Marshal(DeviceCheckRequest{AppVersion: "aio-mod", HWID: "AIO3-" + strings.Repeat("ee", 32)})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/device/check", bytes.NewReader(body))
	req.Header.Set("X-Client-Key", "client-key-abc")
	req.Header.Set("X-Req-Nonce", "99999999999999999999999999999999")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", res.StatusCode)
	}
}

// TestHashBytesStable checks the job-hash helper produces a 64-char hex digest.
func TestHashBytesStable(t *testing.T) {
	a := HashBytes([]byte("some apk contents"))
	b := HashBytes([]byte("some apk contents"))
	c := HashBytes([]byte("some apk content"))
	if a != b {
		t.Error("hash is not deterministic")
	}
	if a == c {
		t.Error("different inputs produced the same hash")
	}
	if len(a) != 64 {
		t.Errorf("hash length = %d, want 64", len(a))
	}
	if _, err := hex.DecodeString(a); err != nil {
		t.Errorf("hash is not hex: %v", err)
	}
}

func encodeB64(b []byte) string {
	const std = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var out strings.Builder
	for i := 0; i < len(b); i += 3 {
		var n uint32
		rem := len(b) - i
		n = uint32(b[i]) << 16
		if rem > 1 {
			n |= uint32(b[i+1]) << 8
		}
		if rem > 2 {
			n |= uint32(b[i+2])
		}
		out.WriteByte(std[(n>>18)&63])
		out.WriteByte(std[(n>>12)&63])
		if rem > 1 {
			out.WriteByte(std[(n>>6)&63])
		} else {
			out.WriteByte('=')
		}
		if rem > 2 {
			out.WriteByte(std[n&63])
		} else {
			out.WriteByte('=')
		}
	}
	return out.String()
}

// TestHMACCoversFields checks the HMAC independently of the signing helper.
//
// The earlier mutations showed why this is needed: replacing the HMAC body with a
// constant still passed, because the verifier called the same helper the signer
// did. A test that computes the expected HMAC itself cannot be fooled that way.
func TestHMACCoversFields(t *testing.T) {
	s, h := newTestServer(t)
	registerVIP(t, s)

	resp, err := s.DeviceCheck(DeviceCheckRequest{AppVersion: "aio-mod", HWID: testHWID}, auth())
	if err != nil {
		t.Fatalf("device check: %v", err)
	}

	// Recompute the HMAC here, from the response's own fields, using the same
	// canonical form the signer uses but this test's own HMAC call.
	msg := canonical(deviceCheckFields(&resp))
	m := hmac.New(sha256.New, s.HMACKey)
	m.Write(msg)
	want := hex.EncodeToString(m.Sum(nil))

	if resp.Sig != want {
		t.Fatalf("sig does not cover the response fields:\n got %s\nwant %s", resp.Sig, want)
	}

	// And it must change when a field changes, proving it is not a constant.
	cp := resp
	cp.Nonce = strings.Repeat("00", 16)
	msg2 := canonical(deviceCheckFields(&cp))
	m2 := hmac.New(sha256.New, s.HMACKey)
	m2.Write(msg2)
	if hex.EncodeToString(m2.Sum(nil)) == want {
		t.Fatal("HMAC is the same for two different field sets: it is not covering them")
	}

	// The Ed25519 signature must also be over the field set and not a constant.
	sig, err := base64.StdEncoding.DecodeString(resp.Ed25519Sig)
	if err != nil {
		t.Fatalf("ed25519_sig not base64: %v", err)
	}
	if !ed25519.Verify(h.Pub, msg, sig) {
		t.Fatal("ed25519 signature does not verify over the recomputed message")
	}
	if ed25519.Verify(h.Pub, []byte("constant"), sig) {
		t.Fatal("ed25519 signature verifies over a constant: it is not binding the message")
	}
}
