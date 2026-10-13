// Command aiolic serves the reversed AIO-MOD license protocol and can verify the
// signatures it produces.
//
// Two modes:
//
//	aiolic serve          run the license server
//	aiolic verify <file>  check the signatures on a recorded response
//
// The server mode is what PLAN.md describes; the verify mode is what makes it
// checkable without the client.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yondaime-kun/aiolic/internal/aiolic"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "verify":
		verify(os.Args[2:])
	case "genkey":
		genkey()
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "aiolic: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `aiolic — server for the reversed AIO-MOD license protocol

  aiolic serve   -addr :8443 -tls-cert <pem> -tls-key <pem> -devices <json>
  aiolic verify  -response <json> -pub <hex> -hmac <hex>
  aiolic genkey

The serve command needs a TLS certificate: the client pins a certificate, so the
server must present one it accepts. Without -tls-cert it listens on plain HTTP,
which is useful for local testing and wrong for the client.
`)
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	addr := fs.String("addr", ":8443", "listen address")
	cert := fs.String("tls-cert", "", "TLS certificate (PEM); omit for plain HTTP")
	key := fs.String("tls-key", "", "TLS private key (PEM)")
	devicesPath := fs.String("devices", "", "JSON file of registered devices")
	clientKey := fs.String("client-key", "", "require this X-Client-Key")
	keyOut := fs.String("key-out", "", "write the signing keys to this file so verify can use them")
	fs.Parse(args)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal(err)
	}
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		fatal(err)
	}
	srv := aiolic.New(priv, hmacKey, *clientKey)

	if *devicesPath != "" {
		if err := loadDevices(srv, *devicesPath); err != nil {
			fatal(err)
		}
	}

	if *keyOut != "" {
		// The keys are written so a recorded response can be checked later. They
		// are the server's own keys, not the vendor's, and are only useful for
		// verifying this server's output.
		out := map[string]string{
			"ed25519_public": hex.EncodeToString(pub),
			"hmac_key":       hex.EncodeToString(hmacKey),
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		if err := os.WriteFile(*keyOut, b, 0o600); err != nil {
			fatal(err)
		}
		fmt.Fprintf(os.Stderr, "keys written to %s\n", *keyOut)
	}

	h := aiolic.NewHandler(srv)
	fmt.Fprintf(os.Stderr, "ed25519 public key: %s\n", hex.EncodeToString(pub))
	fmt.Fprintf(os.Stderr, "listening on %s\n", *addr)

	httpSrv := &http.Server{Addr: *addr, Handler: h.Routes(), ReadHeaderTimeout: 10 * time.Second}
	if *cert != "" && *key != "" {
		if err := httpSrv.ListenAndServeTLS(*cert, *key); err != nil {
			fatal(err)
		}
		return
	}
	fmt.Fprintln(os.Stderr, "note: plain HTTP, no TLS — a stock client will refuse this")
	if err := httpSrv.ListenAndServe(); err != nil {
		fatal(err)
	}
}

// verify checks a recorded response file. The file holds either a device-check
// or a job-claim object, plus optionally the keys.
func verify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	path := fs.String("response", "", "JSON file holding a response")
	pubHex := fs.String("pub", "", "ed25519 public key, hex")
	hmacHex := fs.String("hmac", "", "hmac key, hex")
	kind := fs.String("kind", "auto", "device, claim or auto")
	fs.Parse(args)
	if *path == "" || *pubHex == "" || *hmacHex == "" {
		fatal(fmt.Errorf("-response, -pub and -hmac are required"))
	}
	pubRaw, err := hex.DecodeString(*pubHex)
	if err != nil {
		fatal(fmt.Errorf("-pub is not hex: %w", err))
	}
	if len(pubRaw) != ed25519.PublicKeySize {
		fatal(fmt.Errorf("-pub is %d bytes, want %d", len(pubRaw), ed25519.PublicKeySize))
	}
	pub := ed25519.PublicKey(pubRaw)
	hmacKey, err := hex.DecodeString(*hmacHex)
	if err != nil {
		fatal(fmt.Errorf("-hmac is not hex: %w", err))
	}
	raw, err := os.ReadFile(*path)
	if err != nil {
		fatal(err)
	}

	isDevice := strings.Contains(string(raw), "\"is_vip\"")
	if *kind != "auto" {
		isDevice = *kind == "device"
	}
	if isDevice {
		var r aiolic.DeviceCheckResponse
		if err := json.Unmarshal(raw, &r); err != nil {
			fatal(err)
		}
		if err := aiolic.VerifyDeviceCheck(&r, pub, hmacKey); err != nil {
			fmt.Printf("device-check: INVALID — %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("device-check: valid (hwid=%s vip=%t expires=%s)\n", r.HWID, r.IsVIP, r.ExpiresAt)
		return
	}
	var r aiolic.JobClaimResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		fatal(err)
	}
	if err := aiolic.VerifyJobClaim(&r, pub, hmacKey); err != nil {
		fmt.Printf("job-claim: INVALID — %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("job-claim: valid (feature=%s granted=%t)\n", r.Feature, r.Granted)
}

// loadDevices reads a registry file. Accepts an array of device objects.
func loadDevices(s *aiolic.Server, path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var in []struct {
		HWID         string            `json:"hwid"`
		RegisteredAt string            `json:"registered_at"`
		VIP          bool              `json:"vip"`
		ExpiresAt    string            `json:"expires_at"`
		Jobs         map[string]string `json:"jobs"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return err
	}
	parse := func(s, what string) (time.Time, error) {
		if s == "" {
			return time.Time{}, nil
		}
		for _, layout := range []string{"2006-01-02", time.RFC3339} {
			if t, err := time.Parse(layout, s); err == nil {
				return t, nil
			}
		}
		return time.Time{}, fmt.Errorf("%s: cannot parse %q as a date", what, s)
	}
	for _, d := range in {
		reg, err := parse(d.RegisteredAt, "registered_at")
		if err != nil {
			return err
		}
		exp, err := parse(d.ExpiresAt, "expires_at")
		if err != nil {
			return err
		}
		if err := s.Register(aiolic.Device{
			HWID: d.HWID, RegisteredAt: reg, VIP: d.VIP, ExpiresAt: exp, Jobs: d.Jobs,
		}); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "loaded %d device(s)\n", len(in))
	return nil
}

func genkey() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal(err)
	}
	hmacKey := make([]byte, 32)
	rand.Read(hmacKey)
	fmt.Printf("ed25519_public %s\n", hex.EncodeToString(pub))
	fmt.Printf("ed25519_private %s\n", hex.EncodeToString(priv))
	fmt.Printf("hmac_key %s\n", hex.EncodeToString(hmacKey))
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "aiolic: %v\n", err)
	os.Exit(1)
}
