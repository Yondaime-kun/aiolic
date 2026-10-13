// Package aiolic implements the server half of the AIO-MOD license protocol.
//
// The protocol was reversed from the client (see /home/agentuser/aio-mod-re and
// this repository's PLAN.md). This package is the server that was never written:
// it answers the client's endpoints and signs its responses the way the client
// expects, rather than stubbing the client's verifier out.
//
// Read PLAN.md for the contract and for what this does not claim.
package aiolic

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Signature identifiers, taken from the reversed client.
const (
	// SigAlg is the algorithm the client is told to expect.
	SigAlg = "Ed25519"
	// SigKID is the key id the client was observed to send and receive.
	SigKID = "aio-license-2026-01"
	// UserAgent is what the client sends.
	UserAgent = "AIO-Mod/1.0"
)

// HWIDPrefix is the prefix every hardware id carries.
const HWIDPrefix = "AIO3-"

// Errors the client distinguishes, reproduced so the server can answer with the
// same meaning the client would produce for a failure.
var (
	ErrBadHWID     = errors.New("hardware id is not in the expected form")
	ErrUnknown     = errors.New("device is not registered")
	ErrExpired     = errors.New("entitlement has expired")
	ErrJobHash     = errors.New("job hash is not the one registered for this feature")
	ErrReplay      = errors.New("nonce has already been used")
	ErrSignature   = errors.New("request signature is not valid")
	ErrBadNonce    = errors.New("request nonce is missing or malformed")
	ErrUnknownFeat = errors.New("feature is not known")
)

// Device is one registered installation.
type Device struct {
	HWID         string
	RegisteredAt time.Time
	VIP          bool
	ExpiresAt    time.Time
	// Jobs maps a feature name to the job hash registered for it. The reversed
	// client sends a job_hash that is constant per APK, and the findings note the
	// server can cross-check it, so the server keeps the pair.
	Jobs map[string]string
}

// Server holds the signing keys and the device registry.
type Server struct {
	// EdPriv signs the ed25519_sig field. The client verifies with the
	// matching public key; see PLAN.md for what that implies.
	EdPriv ed25519.PrivateKey
	// HMACKey signs the sig field.
	HMACKey []byte
	// ClientKey is the X-Client-Key the client must present.
	ClientKey string

	devices map[string]*Device
	// seen records request nonces, so a replayed request is refused.
	seen map[string]time.Time
	// now is injectable so tests are not time-dependent.
	now func() time.Time
}

// New returns a server with fresh keys.
func New(edPriv ed25519.PrivateKey, hmacKey []byte, clientKey string) *Server {
	return &Server{
		EdPriv:    edPriv,
		HMACKey:   hmacKey,
		ClientKey: clientKey,
		devices:   map[string]*Device{},
		seen:      map[string]time.Time{},
		now:       time.Now,
	}
}

// Register adds a device. A device registered with vip true is entitled until
// expires.
func (s *Server) Register(d Device) error {
	if !ValidHWID(d.HWID) {
		return ErrBadHWID
	}
	if d.Jobs == nil {
		d.Jobs = map[string]string{}
	}
	cp := d
	s.devices[strings.ToUpper(d.HWID)] = &cp
	return nil
}

// SetJobs replaces the feature to job-hash map for a device.
func (s *Server) SetJobs(hwid string, jobs map[string]string) error {
	dev, ok := s.devices[strings.ToUpper(hwid)]
	if !ok {
		return ErrUnknown
	}
	dev.Jobs = jobs
	return nil
}

// ValidHWID reports whether an id has the documented shape: the AIO3- prefix
// followed by 64 lowercase hex characters.
func ValidHWID(id string) bool {
	if !strings.HasPrefix(id, HWIDPrefix) {
		return false
	}
	rest := id[len(HWIDPrefix):]
	if len(rest) != 64 {
		return false
	}
	_, err := hex.DecodeString(rest)
	return err == nil
}

// DeviceCheckRequest is the body of POST /v1/device/check.
type DeviceCheckRequest struct {
	AppVersion string `json:"app_version"`
	HWID       string `json:"hwid"`
}

// DeviceCheckResponse is the entitlement answer. Field order in the struct is
// the order Go's encoder writes, and the reversed client reads by name, so the
// order is not load-bearing; it is kept close to the observed 509-byte body for
// readability.
type DeviceCheckResponse struct {
	OK           bool   `json:"ok"`
	HWID         string `json:"hwid"`
	RegisteredAt string `json:"registered_at"`
	IsVIP        bool   `json:"is_vip"`
	ExpiresAt    string `json:"expires_at"`
	ServerTime   int64  `json:"server_time"`
	Nonce        string `json:"nonce"`
	ReqNonce     string `json:"req_nonce"`
	SigAlg       string `json:"sig_alg"`
	SigKID       string `json:"sig_kid"`
	Ed25519Sig   string `json:"ed25519_sig"`
	Sig          string `json:"sig"`
}

// JobClaimRequest is the body of POST /v1/job/claim.
type JobClaimRequest struct {
	Feature   string `json:"feature"`
	HWID      string `json:"hwid"`
	JobHash   string `json:"job_hash"`
	RequestID string `json:"request_id"`
}

// JobClaimResponse is the signed grant.
type JobClaimResponse struct {
	OK         bool   `json:"ok"`
	Feature    string `json:"feature"`
	HWID       string `json:"hwid"`
	JobHash    string `json:"job_hash"`
	RequestID  string `json:"request_id"`
	Granted    bool   `json:"granted"`
	ServerTime int64  `json:"server_time"`
	Nonce      string `json:"nonce"`
	ReqNonce   string `json:"req_nonce"`
	SigAlg     string `json:"sig_alg"`
	SigKID     string `json:"sig_kid"`
	Ed25519Sig string `json:"ed25519_sig"`
	Sig        string `json:"sig"`
}

// RequestAuth is the header set the client sends.
type RequestAuth struct {
	ClientKey string
	ReqTime   string
	ReqNonce  string
	ReqSig    string
	UserAgent string
}

// ValidateAuth checks the request headers against the server's client key and
// the nonce replay table.
//
// The reversed client sends X-Client-Key, X-Req-Time, X-Req-Nonce and X-Req-Sig.
// The exact construction of X-Req-Sig was not recovered from the client, so this
// method verifies the parts that are known, and says so rather than pretending
// to check a signature whose formula is unknown.
func (s *Server) ValidateAuth(a RequestAuth) error {
	if s.ClientKey != "" && a.ClientKey != s.ClientKey {
		return ErrSignature
	}
	if a.ReqNonce == "" || len(a.ReqNonce) != 32 {
		return ErrBadNonce
	}
	if _, err := hex.DecodeString(a.ReqNonce); err != nil {
		return ErrBadNonce
	}
	key := strings.ToLower(a.ReqNonce)
	if _, used := s.seen[key]; used {
		return ErrReplay
	}
	s.seen[key] = s.now()
	return nil
}

// ConsumeNonce marks a nonce used. It is called after a request is accepted, so
// a request that fails validation does not burn its nonce.
func (s *Server) ConsumeNonce(a RequestAuth) {
	if a.ReqNonce == "" {
		return
	}
	s.seen[strings.ToLower(a.ReqNonce)] = s.now()
}

// ReleaseNonce undoes a ConsumeNonce for a request that turned out invalid.
func (s *Server) ReleaseNonce(a RequestAuth) {
	delete(s.seen, strings.ToLower(a.ReqNonce))
}

// DeviceCheck answers /v1/device/check.
func (s *Server) DeviceCheck(req DeviceCheckRequest, auth RequestAuth) (DeviceCheckResponse, error) {
	var resp DeviceCheckResponse
	if !ValidHWID(req.HWID) {
		return resp, ErrBadHWID
	}
	if err := s.ValidateAuth(auth); err != nil {
		return resp, err
	}
	dev, ok := s.devices[strings.ToUpper(req.HWID)]
	if !ok {
		// Refuse rather than inventing entitlement: a device the server has not
		// been told about is not VIP.
		s.ReleaseNonce(auth)
		return resp, ErrUnknown
	}
	now := s.now()
	vip := dev.VIP && now.Before(dev.ExpiresAt)
	if !vip {
		s.ReleaseNonce(auth)
		return resp, ErrExpired
	}

	resp = DeviceCheckResponse{
		OK:           true,
		HWID:         dev.HWID,
		RegisteredAt: dev.RegisteredAt.UTC().Format("2006-01-02"),
		IsVIP:        true,
		ExpiresAt:    dev.ExpiresAt.UTC().Format("2006-01-02"),
		ServerTime:   now.Unix(),
		Nonce:        newNonce(),
		ReqNonce:     auth.ReqNonce,
		SigAlg:       SigAlg,
		SigKID:       SigKID,
	}
	s.ConsumeNonce(auth)
	s.signDeviceCheck(&resp)
	return resp, nil
}

// JobClaim answers /v1/job/claim.
func (s *Server) JobClaim(req JobClaimRequest, auth RequestAuth) (JobClaimResponse, error) {
	var resp JobClaimResponse
	if !ValidHWID(req.HWID) {
		return resp, ErrBadHWID
	}
	if req.Feature == "" {
		return resp, ErrUnknownFeat
	}
	if len(req.JobHash) != 64 {
		return resp, ErrJobHash
	}
	if err := s.ValidateAuth(auth); err != nil {
		return resp, err
	}
	dev, ok := s.devices[strings.ToUpper(req.HWID)]
	if !ok {
		s.ReleaseNonce(auth)
		return resp, ErrUnknown
	}
	now := s.now()
	if !dev.VIP || now.After(dev.ExpiresAt) {
		s.ReleaseNonce(auth)
		return resp, ErrExpired
	}
	want, known := dev.Jobs[req.Feature]
	if !known {
		s.ReleaseNonce(auth)
		return resp, ErrUnknownFeat
	}
	// The job hash is constant per APK, so it is the thing that ties a claim to
	// the artifact being worked on. Accepting a claim regardless of it would
	// discard the cross-check the findings describe.
	if !strings.EqualFold(want, req.JobHash) {
		s.ReleaseNonce(auth)
		return resp, ErrJobHash
	}

	resp = JobClaimResponse{
		OK:         true,
		Feature:    req.Feature,
		HWID:       dev.HWID,
		JobHash:    req.JobHash,
		RequestID:  req.RequestID,
		Granted:    true,
		ServerTime: now.Unix(),
		Nonce:      newNonce(),
		ReqNonce:   auth.ReqNonce,
		SigAlg:     SigAlg,
		SigKID:     SigKID,
	}
	s.ConsumeNonce(auth)
	s.signJobClaim(&resp)
	return resp, nil
}

// --- signing ---------------------------------------------------------------

// canonical builds the byte string that is signed.
//
// A signature is only meaningful if both sides agree on exactly what is covered,
// so the covered fields are enumerated here in a fixed order and the checker uses
// this same function. Adding a field means adding it here, which is the point:
// the alternation cannot drift silently between signing and checking.
func canonical(fields [][2]string) []byte {
	sorted := make([][2]string, len(fields))
	copy(sorted, fields)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i][0] < sorted[j][0] })
	var b strings.Builder
	for _, kv := range sorted {
		b.WriteString(kv[0])
		b.WriteByte('=')
		b.WriteString(kv[1])
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// deviceCheckFields enumerates the signed fields of a device-check response.
func deviceCheckFields(r *DeviceCheckResponse) [][2]string {
	return [][2]string{
		{"expires_at", r.ExpiresAt},
		{"hwid", r.HWID},
		{"is_vip", fmt.Sprintf("%t", r.IsVIP)},
		{"nonce", r.Nonce},
		{"ok", fmt.Sprintf("%t", r.OK)},
		{"registered_at", r.RegisteredAt},
		{"req_nonce", r.ReqNonce},
		{"sig_alg", r.SigAlg},
		{"sig_kid", r.SigKID},
		{"server_time", fmt.Sprintf("%d", r.ServerTime)},
	}
}

// jobClaimFields enumerates the signed fields of a job-claim response.
func jobClaimFields(r *JobClaimResponse) [][2]string {
	return [][2]string{
		{"feature", r.Feature},
		{"granted", fmt.Sprintf("%t", r.Granted)},
		{"hwid", r.HWID},
		{"job_hash", r.JobHash},
		{"nonce", r.Nonce},
		{"ok", fmt.Sprintf("%t", r.OK)},
		{"req_nonce", r.ReqNonce},
		{"request_id", r.RequestID},
		{"sig_alg", r.SigAlg},
		{"sig_kid", r.SigKID},
		{"server_time", fmt.Sprintf("%d", r.ServerTime)},
	}
}

func (s *Server) signDeviceCheck(r *DeviceCheckResponse) {
	msg := canonical(deviceCheckFields(r))
	r.Ed25519Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(s.EdPriv, msg))
	r.Sig = hmacHex(s.HMACKey, msg)
}

func (s *Server) signJobClaim(r *JobClaimResponse) {
	msg := canonical(jobClaimFields(r))
	r.Ed25519Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(s.EdPriv, msg))
	r.Sig = hmacHex(s.HMACKey, msg)
}

func hmacHex(key, msg []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return hex.EncodeToString(m.Sum(nil))
}

func newNonce() string {
	var b [16]byte
	for i := range b {
		n := time.Now().UnixNano() >> (uint(i) * 4)
		b[i] = byte(n)
	}
	return hex.EncodeToString(b[:])
}
