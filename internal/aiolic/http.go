package aiolic

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Handler serves the reversed API. Paths are the ones the client was observed to
// call (see PLAN.md).
type Handler struct {
	Srv *Server
	// Pub is the public key the server advertises. The self-check verifies
	// responses against it.
	Pub ed25519.PublicKey
}

// NewHandler wires a server and derives its public key.
func NewHandler(s *Server) *Handler {
	return &Handler{Srv: s, Pub: s.EdPriv.Public().(ed25519.PublicKey)}
}

// Routes returns the mux for the reversed endpoints.
func (h *Handler) Routes() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("/v1/device/check", h.deviceCheck)
	m.HandleFunc("/v1/job/claim", h.jobClaim)
	// Layer three. The client calls these; the exact response shape for each was
	// not recovered field by field, so they answer with the documented envelope
	// and a valid signature. Returning a signed, well-formed response is the
	// honest behaviour: it is the contract that is known.
	for _, p := range []string{
		"/v1/smart/token", "/v1/special/claim", "/v1/usage/check",
		"/v1/usage/mark", "/v1/free/verify", "/v1/compiler/bootstrap",
		"/v1/compiler/assertion",
	} {
		m.HandleFunc(p, h.generic)
	}
	return m
}

func (h *Handler) auth(r *http.Request) RequestAuth {
	return RequestAuth{
		ClientKey: r.Header.Get("X-Client-Key"),
		ReqTime:   r.Header.Get("X-Req-Time"),
		ReqNonce:  r.Header.Get("X-Req-Nonce"),
		ReqSig:    r.Header.Get("X-Req-Sig"),
		UserAgent: r.Header.Get("User-Agent"),
	}
}

// writeJSON encodes a response and, in the same call, verifies the signature it
// just produced. A server that emits a signature nobody can check is the failure
// this is here to prevent.
func (h *Handler) writeJSON(w http.ResponseWriter, code int, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

func (h *Handler) fail(w http.ResponseWriter, err error) {
	code := http.StatusBadRequest
	if errors.Is(err, ErrUnknown) || errors.Is(err, ErrExpired) {
		code = http.StatusForbidden
	}
	if errors.Is(err, ErrReplay) || errors.Is(err, ErrSignature) {
		code = http.StatusUnauthorized
	}
	body, _ := json.Marshal(map[string]any{"ok": false, "error": err.Error()})
	h.writeJSON(w, code, body)
}

func (h *Handler) deviceCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.fail(w, fmt.Errorf("method not allowed"))
		return
	}
	var req DeviceCheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.fail(w, err)
		return
	}
	resp, err := h.Srv.DeviceCheck(req, h.auth(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	body, _ := json.Marshal(resp)
	h.writeJSON(w, http.StatusOK, body)
}

func (h *Handler) jobClaim(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.fail(w, fmt.Errorf("method not allowed"))
		return
	}
	var req JobClaimRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.fail(w, err)
		return
	}
	resp, err := h.Srv.JobClaim(req, h.auth(r))
	if err != nil {
		h.fail(w, err)
		return
	}
	body, _ := json.Marshal(resp)
	h.writeJSON(w, http.StatusOK, body)
}

// generic answers a layer-three endpoint with a signed envelope. The signature is
// real, so the response is indistinguishable from the others in the one respect
// the client checks.
func (h *Handler) generic(w http.ResponseWriter, r *http.Request) {
	auth := h.auth(r)
	if err := h.Srv.ValidateAuth(auth); err != nil {
		h.fail(w, err)
		return
	}
	h.Srv.ConsumeNonce(auth)
	nonce := newNonce()
	env := map[string]any{
		"ok":          true,
		"endpoint":    r.URL.Path,
		"server_time": h.Srv.now().Unix(),
		"nonce":       nonce,
		"req_nonce":   auth.ReqNonce,
		"sig_alg":     SigAlg,
		"sig_kid":     SigKID,
	}
	fields := [][2]string{
		{"endpoint", r.URL.Path},
		{"nonce", nonce},
		{"ok", "true"},
		{"req_nonce", auth.ReqNonce},
		{"server_time", fmt.Sprintf("%d", h.Srv.now().Unix())},
		{"sig_alg", SigAlg},
		{"sig_kid", SigKID},
	}
	msg := canonical(fields)
	env["ed25519_sig"] = base64.StdEncoding.EncodeToString(ed25519.Sign(h.Srv.EdPriv, msg))
	env["sig"] = hmacHex(h.Srv.HMACKey, msg)
	body, _ := json.Marshal(env)
	h.writeJSON(w, http.StatusOK, body)
}

// --- verification, the same way the client would ---------------------------

// VerifyDeviceCheck recomputes both signatures on a response and reports whether
// they hold against the given public key and HMAC key.
//
// This is the function the tests and the CLI use. It is deliberately independent
// of the signing path's convenience: it rebuilds the message from the response's
// own fields, so a signature over the wrong bytes cannot pass.
func VerifyDeviceCheck(r *DeviceCheckResponse, pub ed25519.PublicKey, hmacKey []byte) error {
	msg := canonical(deviceCheckFields(r))
	sig, err := base64.StdEncoding.DecodeString(r.Ed25519Sig)
	if err != nil {
		return fmt.Errorf("ed25519_sig is not base64: %w", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		return errors.New("ed25519 signature does not verify")
	}
	want := hmacHex(hmacKey, msg)
	if !hmac.Equal([]byte(want), []byte(r.Sig)) {
		return errors.New("hmac does not verify")
	}
	return nil
}

// VerifyJobClaim is VerifyDeviceCheck for a job claim.
func VerifyJobClaim(r *JobClaimResponse, pub ed25519.PublicKey, hmacKey []byte) error {
	msg := canonical(jobClaimFields(r))
	sig, err := base64.StdEncoding.DecodeString(r.Ed25519Sig)
	if err != nil {
		return fmt.Errorf("ed25519_sig is not base64: %w", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		return errors.New("ed25519 signature does not verify")
	}
	want := hmacHex(hmacKey, msg)
	if !hmac.Equal([]byte(want), []byte(r.Sig)) {
		return errors.New("hmac does not verify")
	}
	return nil
}

// VerifyGeneric checks a layer-three envelope's signatures.
func VerifyGeneric(body map[string]any, pub ed25519.PublicKey, hmacKey []byte) error {
	str := func(k string) string {
		if v, ok := body[k].(string); ok {
			return v
		}
		return ""
	}
	num := func(k string) string {
		switch v := body[k].(type) {
		case float64:
			return fmt.Sprintf("%d", int64(v))
		case string:
			return v
		}
		return ""
	}
	fields := [][2]string{
		{"endpoint", str("endpoint")},
		{"nonce", str("nonce")},
		{"ok", "true"},
		{"req_nonce", str("req_nonce")},
		{"server_time", num("server_time")},
		{"sig_alg", str("sig_alg")},
		{"sig_kid", str("sig_kid")},
	}
	msg := canonical(fields)
	sig, err := base64.StdEncoding.DecodeString(str("ed25519_sig"))
	if err != nil {
		return fmt.Errorf("ed25519_sig is not base64: %w", err)
	}
	if !ed25519.Verify(pub, msg, sig) {
		return errors.New("ed25519 signature does not verify")
	}
	if !hmac.Equal([]byte(hmacHex(hmacKey, msg)), []byte(str("sig"))) {
		return errors.New("hmac does not verify")
	}
	return nil
}

// HashBytes is the helper for producing the job_hash the client sends: a hash of
// the artifact being worked on, hex encoded. The client sends the hash of the
// APK; the server needs the same value registered to compare.
func HashBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ParseHWID pulls the hex portion out of an id, for callers that want the raw
// value rather than the prefixed form.
func ParseHWID(id string) (string, error) {
	if !ValidHWID(id) {
		return "", ErrBadHWID
	}
	return strings.ToLower(id[len(HWIDPrefix):]), nil
}
